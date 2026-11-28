//! A phone or laptop near the rabbit: a Wi-Fi client for when the
//! rabbit itself is the access point (setup mode). It finds the
//! rabbit's network, joins it, takes an address from the rabbit's DHCP
//! server and fetches pages from its configuration server.

use std::collections::VecDeque;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{dhcpv4, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

use crate::air::{Mac, element, mac_header};
use crate::lan::Wire;
use crate::rt2573::{Radio, RxFrame};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// Listening for a beacon of the wanted network.
    Searching,
    Authenticating,
    Associating,
    Associated,
}

/// An answer from the rabbit's web server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The request line that was sent.
    pub request: String,
    /// Everything received until the rabbit closed the connection.
    pub raw: Vec<u8>,
}

impl Page {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.raw).into_owned()
    }
}

pub struct Visitor {
    pub mac: Mac,
    /// Networks whose name starts with this are joined.
    pub network_prefix: String,
    pub link: Link,
    /// Name and address of the network found.
    pub network: Option<(String, Mac)>,
    /// Address obtained from the rabbit's DHCP server.
    pub address: Option<[u8; 4]>,
    /// Address of the DHCP server and gateway.
    pub server: Option<[u8; 4]>,
    /// Answers received, in order.
    pub pages: Vec<Page>,
    queue: VecDeque<Vec<u8>>,
    sending: Option<(String, Vec<u8>, usize)>,
    received: Vec<u8>,
    wire: Wire,
    iface: Interface,
    sockets: SocketSet<'static>,
    dhcp: SocketHandle,
    tcp: SocketHandle,
    port: u16,
    heard: usize,
    seq: u16,
    retry_at: u64,
}

const LLC_SNAP: [u8; 6] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];
const RETRY_MS: u64 = 500;

impl Visitor {
    pub fn new(mac: Mac, network_prefix: &str) -> Self {
        let mut wire = Wire {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        };
        let config = Config::new(EthernetAddress(mac).into());
        let iface = Interface::new(config, &mut wire, Instant::from_millis(0));
        let mut sockets = SocketSet::new(vec![]);
        let dhcp = sockets.add(dhcpv4::Socket::new());
        let buffer = || tcp::SocketBuffer::new(vec![0; 64 * 1024]);
        let tcp = sockets.add(tcp::Socket::new(buffer(), buffer()));
        Visitor {
            mac,
            network_prefix: network_prefix.to_string(),
            link: Link::Searching,
            network: None,
            address: None,
            server: None,
            pages: Vec::new(),
            queue: VecDeque::new(),
            sending: None,
            received: Vec::new(),
            wire,
            iface,
            sockets,
            dhcp,
            tcp,
            port: 49152,
            heard: 0,
            seq: 0,
            retry_at: 0,
        }
    }

    /// Ask for a page, as a browser would: `get("/a.htm")`.
    pub fn get(&mut self, target: &str) {
        self.queue
            .push_back(format!("GET {target} HTTP/1.0\r\nHost: 192.168.0.1\r\n\r\n").into_bytes());
    }

    /// Post a body to the rabbit, as the firmware upload form does.
    pub fn post(&mut self, target: &str, body: &[u8]) {
        let mut request = format!(
            "POST {target} HTTP/1.0\r\nHost: 192.168.0.1\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        self.queue.push_back(request);
    }

    /// Requests not answered yet.
    pub fn pending(&self) -> usize {
        self.queue.len() + self.sending.is_some() as usize
    }

    fn bssid(&self) -> Mac {
        self.network.as_ref().map_or([0; 6], |n| n.1)
    }

    fn send_frame(&mut self, radio: &mut Radio, fc0: u8, fc1: u8, a3: Mac, body: &[u8]) {
        let bssid = self.bssid();
        let mut f = mac_header(fc0, fc1, bssid, self.mac, a3, &mut self.seq);
        f.extend_from_slice(body);
        radio.rx.push_back(RxFrame::new(f));
    }

    fn send_authentication(&mut self, radio: &mut Radio) {
        // Open system, first frame of the exchange.
        self.send_frame(radio, 0xB0, 0, self.bssid(), &[0, 0, 1, 0, 0, 0]);
    }

    fn send_association(&mut self, radio: &mut Radio) {
        let name = self
            .network
            .as_ref()
            .map(|n| n.0.clone())
            .unwrap_or_default();
        let mut body = vec![0x01, 0x04, 10, 0, 0, name.len() as u8];
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(&[1, 4, 0x82, 0x84, 0x8B, 0x96]);
        self.send_frame(radio, 0x00, 0, self.bssid(), &body);
    }

    /// Live for a moment: follow the link, then the network on top.
    pub fn poll(&mut self, radio: &mut Radio, now_ms: u64) {
        let fresh: Vec<Vec<u8>> = radio
            .tx
            .iter()
            .skip(self.heard)
            .filter(|f| f.data.len() >= 24)
            .map(|f| f.data.clone())
            .collect();
        self.heard = radio.tx.len();
        for frame in fresh {
            self.on_frame(radio, &frame, now_ms);
        }
        if self.retry_at != 0 && now_ms >= self.retry_at {
            self.retry_at = now_ms + RETRY_MS;
            match self.link {
                Link::Authenticating => self.send_authentication(radio),
                Link::Associating => self.send_association(radio),
                _ => self.retry_at = 0,
            }
        }
        if self.link != Link::Associated {
            return;
        }

        let now = Instant::from_millis(now_ms as i64);
        self.iface.poll(now, &mut self.wire, &mut self.sockets);
        self.follow_dhcp();
        self.browse();
        self.iface.poll(now, &mut self.wire, &mut self.sockets);
        while let Some(eth) = self.wire.tx.pop_front() {
            let dst: Mac = eth[..6].try_into().unwrap();
            let mut body = LLC_SNAP.to_vec();
            body.extend_from_slice(&eth[12..]);
            self.send_frame(radio, 0x08, 0x01, dst, &body);
        }
    }

    fn on_frame(&mut self, radio: &mut Radio, frame: &[u8], now_ms: u64) {
        let to: Mac = frame[4..10].try_into().unwrap();
        let from: Mac = frame[10..16].try_into().unwrap();
        let body = &frame[24..];
        let for_me = to == self.mac;
        match (frame[0], self.link) {
            (0x80, Link::Searching) => {
                let Some(name) = body.get(12..).and_then(|ies| element(ies, 0)) else {
                    return;
                };
                let name = String::from_utf8_lossy(name).into_owned();
                if !name.starts_with(&self.network_prefix) {
                    return;
                }
                self.network = Some((name, from));
                self.link = Link::Authenticating;
                self.retry_at = now_ms + RETRY_MS;
                self.send_authentication(radio);
            }
            (0xB0, Link::Authenticating)
                if for_me && body.len() >= 6 && body[2..6] == [2, 0, 0, 0] =>
            {
                self.link = Link::Associating;
                self.retry_at = now_ms + RETRY_MS;
                self.send_association(radio);
            }
            (0x10, Link::Associating) if for_me && body.len() >= 4 && body[2..4] == [0, 0] => {
                self.link = Link::Associated;
                self.retry_at = 0;
            }
            (0xC0 | 0xA0, _) if for_me && from == self.bssid() => {
                self.link = Link::Searching;
                self.address = None;
            }
            (0x08, Link::Associated) if frame[1] & 3 == 2 && from == self.bssid() => {
                if !(for_me || to[0] & 1 != 0) || body.len() < 8 || body[..6] != LLC_SNAP {
                    return;
                }
                let mut eth = to.to_vec();
                eth.extend_from_slice(&frame[16..22]);
                eth.extend_from_slice(&body[6..]);
                self.wire.rx.push_back(eth);
            }
            _ => {}
        }
    }

    fn follow_dhcp(&mut self) {
        let event = self.sockets.get_mut::<dhcpv4::Socket>(self.dhcp).poll();
        match event {
            Some(dhcpv4::Event::Configured(config)) => {
                self.address = Some(config.address.address().octets());
                self.server = Some(config.server.address.octets());
                self.iface.update_ip_addrs(|addrs| {
                    addrs.clear();
                    addrs.push(IpCidr::Ipv4(config.address)).unwrap();
                });
            }
            Some(dhcpv4::Event::Deconfigured) => {
                self.address = None;
                self.iface.update_ip_addrs(|addrs| addrs.clear());
            }
            None => {}
        }
    }

    /// One request at a time: connect, send, read until the rabbit hangs up.
    fn browse(&mut self) {
        let Some(server) = self.server.filter(|_| self.address.is_some()) else {
            return;
        };
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp);
        if self.sending.is_none() {
            if socket.is_open() {
                return;
            }
            let Some(request) = self.queue.pop_front() else {
                return;
            };
            let line = String::from_utf8_lossy(&request)
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            self.port = if self.port == 65535 {
                49152
            } else {
                self.port + 1
            };
            let [a, b, c, d] = server;
            if socket
                .connect(
                    self.iface.context(),
                    (IpAddress::v4(a, b, c, d), 80),
                    self.port,
                )
                .is_err()
            {
                return;
            }
            self.sending = Some((line, request, 0));
            self.received.clear();
            return;
        }
        let (_, request, sent) = self.sending.as_mut().unwrap();
        if *sent < request.len() && socket.can_send() {
            *sent += socket.send_slice(&request[*sent..]).unwrap_or(0);
        }
        while socket.can_recv() {
            let _ = socket.recv(|data| {
                self.received.extend_from_slice(data);
                (data.len(), ())
            });
        }
        let done = *sent == request.len() && !socket.may_recv();
        if done || !socket.is_open() {
            socket.close();
            let (request, ..) = self.sending.take().unwrap();
            self.pages.push(Page {
                request,
                raw: std::mem::take(&mut self.received),
            });
        }
    }
}
