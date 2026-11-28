//! The wired side of the access points: one host that plays everything
//! the rabbit talks to. It hands out an address (DHCP), answers every
//! name with its own address (DNS) and serves HTTP on port 80, so a
//! rabbit can fetch its bytecode the way it does from a real server.

use std::collections::{BTreeMap, VecDeque};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint};

pub const GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
pub const GATEWAY_IP: [u8; 4] = [192, 168, 1, 1];
pub const NETMASK: [u8; 4] = [255, 255, 255, 0];
/// The address the first (and only) DHCP client is given.
pub const LEASE_IP: [u8; 4] = [192, 168, 1, 100];

const HTTP_SOCKETS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// Path and query string, as on the request line.
    pub target: String,
    pub headers: String,
    pub body: Vec<u8>,
}

impl Request {
    /// Value of a header, whatever its case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Response {
            status: 200,
            body: body.into(),
        }
    }

    pub fn not_found() -> Self {
        Response {
            status: 404,
            body: b"not found".to_vec(),
        }
    }
}

/// A UDP datagram sent by a station.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub to: [u8; 4],
    pub from_port: u16,
    pub to_port: u16,
    pub payload: Vec<u8>,
}

pub(crate) struct Wire {
    pub(crate) rx: VecDeque<Vec<u8>>,
    pub(crate) tx: VecDeque<Vec<u8>>,
}

pub(crate) struct Rx(Vec<u8>);
pub(crate) struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; len];
        let r = f(&mut frame);
        self.0.push_back(frame);
        r
    }
}

impl Wire {
    /// An empty wire, and a network interface of address `mac` on it.
    pub(crate) fn with_interface(mac: [u8; 6]) -> (Wire, Interface) {
        let mut wire = Wire {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        };
        let config = Config::new(EthernetAddress(mac).into());
        let iface = Interface::new(config, &mut wire, Instant::from_millis(0));
        (wire, iface)
    }
}

impl Device for Wire {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        let frame = self.rx.pop_front()?;
        Some((Rx(frame), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps
    }
}

struct Connection {
    handle: SocketHandle,
    inbox: Vec<u8>,
    outbox: Vec<u8>,
    answered: bool,
    /// The answer went out whole, all of it acknowledged.
    delivered: bool,
}

pub struct Lan {
    wire: Wire,
    iface: Interface,
    sockets: SocketSet<'static>,
    dns: SocketHandle,
    http: Vec<Connection>,
    /// Decides what every HTTP request gets back.
    pub handler: Box<dyn FnMut(&Request) -> Response>,
    /// Requests served, in order.
    pub requests: Vec<Request>,
    /// When each answer was all acknowledged by the station, in board
    /// milliseconds, in the order of the requests.
    pub delivered_ms: Vec<u64>,
    /// Names asked to the DNS server, in order.
    pub dns_queries: Vec<String>,
    /// DHCP message types received (1 discover, 3 request, ...).
    pub dhcp_messages: Vec<u8>,
    /// Hardware address the lease was acknowledged to.
    pub leased_to: Option<[u8; 6]>,
    /// Every UDP datagram the stations sent, in order.
    pub datagrams: Vec<Datagram>,
    /// Addresses for specific names; everything else is the gateway.
    pub hosts: BTreeMap<String, [u8; 4]>,
}

impl Default for Lan {
    fn default() -> Self {
        Self::new()
    }
}

/// The IPv4 packet an Ethernet frame carries, if it carries UDP.
fn udp_packet(frame: &[u8]) -> Option<&[u8]> {
    if frame.get(12..14)? != [0x08, 0x00] || frame.get(23)? != &17 {
        return None;
    }
    Some(&frame[14..])
}

/// An Ethernet frame from the gateway with a UDP datagram in it.
fn udp_frame(to: ([u8; 6], [u8; 4]), ports: (u16, u16), payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&(20 + udp_len).to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
    packet.extend_from_slice(&GATEWAY_IP);
    packet.extend_from_slice(&to.1);
    let sum = checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(&ports.0.to_be_bytes());
    packet.extend_from_slice(&ports.1.to_be_bytes());
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(payload);
    let mut eth = to.0.to_vec();
    eth.extend_from_slice(&GATEWAY_MAC);
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&packet);
    eth
}

/// The internet checksum (RFC 1071) of IPv4, UDP and TCP headers.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        sum += (pair[0] as u32) << 8 | *pair.get(1).unwrap_or(&0) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

impl Lan {
    pub fn new() -> Self {
        let (wire, mut iface) = Wire::with_interface(GATEWAY_MAC);
        let [a, b, c, d] = GATEWAY_IP;
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(a, b, c, d), 24))
                .unwrap();
        });
        let mut sockets = SocketSet::new(vec![]);
        let packets = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 4096]);
        let dns = sockets.add(udp::Socket::new(packets(), packets()));
        let http = (0..HTTP_SOCKETS)
            .map(|_| {
                let buffer = || tcp::SocketBuffer::new(vec![0; 16 * 1024]);
                Connection {
                    handle: sockets.add(tcp::Socket::new(buffer(), buffer())),
                    inbox: Vec::new(),
                    outbox: Vec::new(),
                    answered: false,
                    delivered: false,
                }
            })
            .collect();
        Lan {
            wire,
            iface,
            sockets,
            dns,
            http,
            handler: Box::new(|_| Response::not_found()),
            requests: Vec::new(),
            delivered_ms: Vec::new(),
            dns_queries: Vec::new(),
            dhcp_messages: Vec::new(),
            leased_to: None,
            datagrams: Vec::new(),
            hosts: BTreeMap::new(),
        }
    }

    /// An Ethernet frame arriving from a station.
    pub fn input(&mut self, frame: Vec<u8>) {
        self.note_datagram(&frame);
        if let Some(reply) = self.dhcp(&frame) {
            self.wire.tx.push_back(reply);
        } else {
            self.wire.rx.push_back(frame);
        }
    }

    /// Next Ethernet frame to deliver to the stations.
    pub fn output(&mut self) -> Option<Vec<u8>> {
        self.wire.tx.pop_front()
    }

    /// Keep a copy of every UDP datagram the stations send.
    fn note_datagram(&mut self, frame: &[u8]) -> Option<()> {
        let ip = udp_packet(frame)?;
        let total = u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]) as usize;
        let udp = ip.get((ip[0] & 0xF) as usize * 4..total)?;
        self.datagrams.push(Datagram {
            to: ip[16..20].try_into().unwrap(),
            from_port: u16::from_be_bytes([*udp.first()?, *udp.get(1)?]),
            to_port: u16::from_be_bytes([*udp.get(2)?, *udp.get(3)?]),
            payload: udp.get(8..)?.to_vec(),
        });
        Some(())
    }

    /// Send a UDP datagram from the gateway to the station that holds
    /// the lease. Returns false while nobody does.
    pub fn send_udp(&mut self, from_port: u16, to_port: u16, payload: &[u8]) -> bool {
        let Some(station) = self.leased_to else {
            return false;
        };
        let eth = udp_frame((station, LEASE_IP), (from_port, to_port), payload);
        self.wire.tx.push_back(eth);
        true
    }

    /// Answer a DHCP discover or request; `None` if the frame is not one.
    fn dhcp(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        let ip = udp_packet(frame)?;
        let udp = ip.get((ip[0] & 0xF) as usize * 4..)?;
        if udp.get(2..4)? != [0, 67] {
            return None;
        }
        let bootp = udp.get(8..)?;
        if bootp.len() < 240 || bootp[0] != 1 || bootp[236..240] != [99, 130, 83, 99] {
            return None;
        }
        let mut kind = 0;
        let mut options = &bootp[240..];
        while let [code, rest @ ..] = options {
            match (*code, rest) {
                (255, _) => break,
                (0, _) => options = rest,
                (code, [len, body @ ..]) => {
                    let value = body.get(..*len as usize)?;
                    if code == 53 {
                        kind = *value.first()?;
                    }
                    options = &body[*len as usize..];
                }
                _ => break,
            }
        }
        self.dhcp_messages.push(kind);
        let answer = match kind {
            1 => 2, // discover -> offer
            3 => 5, // request -> acknowledge
            _ => return None,
        };
        let client: [u8; 6] = bootp[28..34].try_into().unwrap();
        if answer == 5 {
            self.leased_to = Some(client);
        }

        let mut reply = vec![0u8; 240];
        reply[0] = 2;
        reply[1] = 1;
        reply[2] = 6;
        reply[4..8].copy_from_slice(&bootp[4..8]);
        reply[10..12].copy_from_slice(&bootp[10..12]);
        reply[16..20].copy_from_slice(&LEASE_IP);
        reply[20..24].copy_from_slice(&GATEWAY_IP);
        reply[28..44].copy_from_slice(&bootp[28..44]);
        reply[236..240].copy_from_slice(&[99, 130, 83, 99]);
        reply.extend_from_slice(&[53, 1, answer]);
        reply.extend_from_slice(&[54, 4]);
        reply.extend_from_slice(&GATEWAY_IP);
        reply.extend_from_slice(&[51, 4, 0, 1, 0x51, 0x80]);
        reply.extend_from_slice(&[1, 4]);
        reply.extend_from_slice(&NETMASK);
        reply.extend_from_slice(&[3, 4]);
        reply.extend_from_slice(&GATEWAY_IP);
        reply.extend_from_slice(&[6, 4]);
        reply.extend_from_slice(&GATEWAY_IP);
        reply.push(255);

        Some(udp_frame(([0xFF; 6], [255; 4]), (67, 68), &reply))
    }

    /// Let the host work: its network stack, then its servers.
    pub fn poll(&mut self, now_ms: u64) {
        let now = Instant::from_millis(now_ms as i64);
        self.iface.poll(now, &mut self.wire, &mut self.sockets);
        self.serve_dns();
        self.serve_http(now_ms);
        self.iface.poll(now, &mut self.wire, &mut self.sockets);
    }

    fn serve_dns(&mut self) {
        let socket = self.sockets.get_mut::<udp::Socket>(self.dns);
        if !socket.is_open() {
            socket.bind(53).unwrap();
        }
        while let Ok((query, meta)) = socket.recv() {
            let query = query.to_vec();
            let from: IpEndpoint = meta.endpoint;
            let Some((name, question_end, qtype)) = parse_question(&query) else {
                continue;
            };
            self.dns_queries.push(name.clone());
            let address = self.hosts.get(&name).copied().unwrap_or(GATEWAY_IP);
            let is_a = qtype == 1;
            let mut reply = query[..2].to_vec();
            reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, is_a as u8, 0, 0, 0, 0]);
            reply.extend_from_slice(&query[12..question_end]);
            if is_a {
                reply.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                reply.extend_from_slice(&address);
            }
            let _ = socket.send_slice(&reply, from);
        }
    }

    fn serve_http(&mut self, now_ms: u64) {
        for conn in &mut self.http {
            let socket = self.sockets.get_mut::<tcp::Socket>(conn.handle);
            if !socket.is_open() {
                conn.inbox.clear();
                conn.outbox.clear();
                conn.answered = false;
                conn.delivered = false;
                socket.listen(80).unwrap();
                continue;
            }
            while socket.can_recv() {
                let _ = socket.recv(|data| {
                    conn.inbox.extend_from_slice(data);
                    (data.len(), ())
                });
            }
            if !conn.answered
                && let Some(request) = parse_request(&conn.inbox)
            {
                let response = (self.handler)(&request);
                self.requests.push(request);
                let reason = if response.status == 200 {
                    "OK"
                } else {
                    "Error"
                };
                conn.outbox = format!(
                    "HTTP/1.0 {} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.status,
                    response.body.len()
                )
                .into_bytes();
                conn.outbox.extend_from_slice(&response.body);
                conn.answered = true;
            }
            if !conn.outbox.is_empty() && socket.can_send() {
                let sent = socket.send_slice(&conn.outbox).unwrap_or(0);
                conn.outbox.drain(..sent);
            }
            if conn.answered && conn.outbox.is_empty() && socket.send_queue() == 0 {
                if !conn.delivered {
                    conn.delivered = true;
                    self.delivered_ms.push(now_ms);
                }
                socket.close();
            }
            if !socket.may_recv() && !conn.answered && socket.state() == tcp::State::CloseWait {
                // The client gave up before sending a whole request.
                socket.close();
            }
        }
    }
}

/// Name, end offset and type of the first question of a DNS query.
fn parse_question(q: &[u8]) -> Option<(String, usize, u16)> {
    if q.len() < 12 || q[2] & 0x80 != 0 || q[4..6] != [0, 1] {
        return None;
    }
    let mut at = 12;
    let mut labels = Vec::new();
    loop {
        let len = *q.get(at)? as usize;
        at += 1;
        if len == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(q.get(at..at + len)?).to_lowercase());
        at += len;
    }
    let qtype = u16::from_be_bytes([*q.get(at)?, *q.get(at + 1)?]);
    Some((labels.join("."), at + 4, qtype))
}

/// A complete HTTP request out of the bytes received so far.
fn parse_request(raw: &[u8]) -> Option<Request> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let (line, headers) = head.split_once("\r\n").unwrap_or((&head, ""));
    let mut words = line.split(' ');
    let mut request = Request {
        method: words.next()?.to_string(),
        target: words.next()?.to_string(),
        headers: headers.to_string(),
        body: Vec::new(),
    };
    let length = request
        .header("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    request.body = raw.get(end + 4..end + 4 + length)?.to_vec();
    Some(request)
}
