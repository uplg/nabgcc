//! The Rust firmware against a real hostapd, on Linux: hostapd drives a
//! radio of the kernel's `mac80211_hwsim`, and this test stands where
//! wmediumd would, carrying frames between that radio and the emulated
//! rabbit's stick. The cipher on the access point's side is the
//! kernel's own. `scripts/hostapd-interop.sh` sets the scene (hwsim,
//! hostapd, dnsmasq, a web server) and runs this test once per kind of
//! network; without `NABEMU_HOSTAPD_RADIO` it is skipped.

#[cfg(target_os = "linux")]
mod hwsim {
    use std::io;

    const NETLINK_GENERIC: i32 = 16;
    const GENL_ID_CTRL: u16 = 0x10;
    const CTRL_CMD_GETFAMILY: u8 = 3;
    const CTRL_ATTR_FAMILY_ID: u16 = 1;
    const CTRL_ATTR_FAMILY_NAME: u16 = 2;
    const NLM_F_REQUEST: u16 = 1;

    const CMD_REGISTER: u8 = 1;
    const CMD_FRAME: u8 = 2;
    const CMD_TX_INFO_FRAME: u8 = 3;
    const ATTR_ADDR_RECEIVER: u16 = 1;
    const ATTR_ADDR_TRANSMITTER: u16 = 2;
    const ATTR_FRAME: u16 = 3;
    const ATTR_FLAGS: u16 = 4;
    const ATTR_RX_RATE: u16 = 5;
    const ATTR_SIGNAL: u16 = 6;
    const ATTR_TX_INFO: u16 = 7;
    const ATTR_COOKIE: u16 = 8;
    const ATTR_FREQ: u16 = 19;
    const TX_STAT_ACK: u32 = 4;

    pub struct Hwsim {
        fd: i32,
        family: u16,
        seq: u32,
    }

    /// A frame a simulated radio sent.
    pub struct Sent {
        pub transmitter: [u8; 6],
        pub frame: Vec<u8>,
        pub flags: u32,
        pub tx_info: Vec<u8>,
        pub cookie: u64,
    }

    fn attr(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
        out.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }

    fn attrs(mut b: &[u8]) -> Vec<(u16, &[u8])> {
        let mut out = Vec::new();
        while b.len() >= 4 {
            let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
            let kind = u16::from_ne_bytes([b[2], b[3]]) & 0x3FFF;
            if len < 4 || len > b.len() {
                break;
            }
            out.push((kind, &b[4..len]));
            b = &b[((len + 3) & !3).min(b.len())..];
        }
        out
    }

    impl Hwsim {
        pub fn open() -> io::Result<Hwsim> {
            // SAFETY: plain socket calls, the address is a zeroed
            // sockaddr_nl of the right size.
            let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_GENERIC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            addr.nl_family = libc::AF_NETLINK as u16;
            let r = unsafe {
                libc::bind(
                    fd,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as u32,
                )
            };
            if r < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut h = Hwsim {
                fd,
                family: GENL_ID_CTRL,
                seq: 1,
            };
            let mut a = Vec::new();
            attr(&mut a, CTRL_ATTR_FAMILY_NAME, b"MAC80211_HWSIM\0");
            h.send(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, &a)?;
            let reply = h.recv(true)?.ok_or(io::ErrorKind::NotFound)?;
            let id = attrs(&reply.1)
                .into_iter()
                .find(|(k, _)| *k == CTRL_ATTR_FAMILY_ID)
                .map(|(_, v)| u16::from_ne_bytes([v[0], v[1]]))
                .ok_or(io::ErrorKind::NotFound)?;
            h.family = id;
            h.send(id, CMD_REGISTER, &[])?;
            Ok(h)
        }

        fn send(&mut self, family: u16, cmd: u8, payload: &[u8]) -> io::Result<()> {
            let mut m = Vec::new();
            m.extend_from_slice(&((20 + payload.len()) as u32).to_ne_bytes());
            m.extend_from_slice(&family.to_ne_bytes());
            m.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
            m.extend_from_slice(&self.seq.to_ne_bytes());
            m.extend_from_slice(&0u32.to_ne_bytes());
            m.extend_from_slice(&[cmd, 1, 0, 0]);
            m.extend_from_slice(payload);
            self.seq += 1;
            // SAFETY: a buffer of `m.len()` bytes.
            let n = unsafe { libc::send(self.fd, m.as_ptr().cast(), m.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// One generic netlink message: its command and attributes.
        fn recv(&mut self, wait: bool) -> io::Result<Option<(u8, Vec<u8>)>> {
            let mut buf = vec![0u8; 8192];
            let flags = if wait { 0 } else { libc::MSG_DONTWAIT };
            // SAFETY: a buffer of `buf.len()` bytes.
            let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr().cast(), buf.len(), flags) };
            if n < 0 {
                let e = io::Error::last_os_error();
                return if e.kind() == io::ErrorKind::WouldBlock {
                    Ok(None)
                } else {
                    Err(e)
                };
            }
            let n = n as usize;
            if n < 20 {
                return Ok(None);
            }
            let len = (u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize).min(n);
            let kind = u16::from_ne_bytes([buf[4], buf[5]]);
            if kind == 2 {
                // An error (or an acknowledgement) of our requests.
                let code = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
                if code != 0 {
                    eprintln!("hwsim refused a request: error {code}");
                }
                return Ok(None);
            }
            Ok(Some((buf[16], buf[20..len].to_vec())))
        }

        /// The next frame one of the radios sent, if any.
        pub fn sent(&mut self) -> io::Result<Option<Sent>> {
            loop {
                let Some((cmd, payload)) = self.recv(false)? else {
                    return Ok(None);
                };
                if cmd != CMD_FRAME {
                    continue;
                }
                let mut s = Sent {
                    transmitter: [0; 6],
                    frame: Vec::new(),
                    flags: 0,
                    tx_info: Vec::new(),
                    cookie: 0,
                };
                for (k, v) in attrs(&payload) {
                    match k {
                        ATTR_ADDR_TRANSMITTER if v.len() >= 6 => {
                            s.transmitter.copy_from_slice(&v[..6])
                        }
                        ATTR_FRAME => s.frame = v.to_vec(),
                        ATTR_FLAGS if v.len() >= 4 => {
                            s.flags = u32::from_ne_bytes([v[0], v[1], v[2], v[3]])
                        }
                        ATTR_TX_INFO => s.tx_info = v.to_vec(),
                        ATTR_COOKIE if v.len() >= 8 => {
                            s.cookie = u64::from_ne_bytes(v[..8].try_into().unwrap())
                        }
                        _ => {}
                    }
                }
                return Ok(Some(s));
            }
        }

        /// Report how a sent frame went: acknowledged or not.
        pub fn status(&mut self, s: &Sent, acked: bool) -> io::Result<()> {
            let mut a = Vec::new();
            attr(&mut a, ATTR_ADDR_TRANSMITTER, &s.transmitter);
            let flags = s.flags | if acked { TX_STAT_ACK } else { 0 };
            attr(&mut a, ATTR_FLAGS, &flags.to_ne_bytes());
            attr(&mut a, ATTR_SIGNAL, &(-50i32).to_ne_bytes());
            attr(&mut a, ATTR_TX_INFO, &s.tx_info);
            attr(&mut a, ATTR_COOKIE, &s.cookie.to_ne_bytes());
            self.send(self.family, CMD_TX_INFO_FRAME, &a)
        }

        /// Hand a frame to the radio with this address, on `freq` MHz.
        pub fn deliver(&mut self, radio: &[u8; 6], frame: &[u8], freq: u32) -> io::Result<()> {
            let mut a = Vec::new();
            attr(&mut a, ATTR_ADDR_RECEIVER, radio);
            attr(&mut a, ATTR_FRAME, frame);
            attr(&mut a, ATTR_RX_RATE, &1u32.to_ne_bytes());
            attr(&mut a, ATTR_SIGNAL, &(-50i32).to_ne_bytes());
            attr(&mut a, ATTR_FREQ, &freq.to_ne_bytes());
            self.send(self.family, CMD_FRAME, &a)
        }
    }

    impl Drop for Hwsim {
        fn drop(&mut self) {
            // SAFETY: our own descriptor.
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn lapin_against_hostapd() {
    use nabemu::config::{Config, Wifi};
    use nabemu::rt2573::RxFrame;
    use nabemu::{DEFAULT_MAC, Machine};

    let Ok(radio) = std::env::var("NABEMU_HOSTAPD_RADIO") else {
        eprintln!("skipped: no NABEMU_HOSTAPD_RADIO (scripts/hostapd-interop.sh)");
        return;
    };
    let radio: Vec<u8> = radio
        .split(':')
        .map(|h| u8::from_str_radix(h, 16).unwrap())
        .collect();
    let mut radio: [u8; 6] = radio.try_into().unwrap();
    let wifi = match std::env::var("NABEMU_HOSTAPD_WIFI").as_deref() {
        Ok("open") => Wifi::Open,
        Ok("wpa") => Wifi::Wpa {
            passphrase: "carotte-violette".into(),
        },
        _ => Wifi::Wpa2 {
            passphrase: "carotte-violette".into(),
        },
    };
    let expect = std::env::var("NABEMU_HOSTAPD_EXPECT").unwrap_or_else(|_| "4242".into());
    let mut m = Machine::from_file(&nabemu::testing::image()).0;
    let mut config = Config::new("Terrier", wifi);
    config.server = "192.168.50.1/vl".into();
    config.install(&mut m.soc.flash);
    let mut hw = hwsim::Hwsim::open().expect("mac80211_hwsim over generic netlink");
    // 2437 MHz: channel 6, where hostapd is.
    const CHANNEL: u8 = 6;
    const FREQ: u32 = 2437;
    let limit = 90_000;
    let mut sent_by_rabbit = 0;
    let mut heard_by_rabbit = 0;
    while m.soc.millis() < limit && !m.console().contains(&expect) {
        m.run_until_ms(m.soc.millis() + 1);
        // The rabbit's frames, to hostapd's radio when on its channel.
        let out: Vec<_> = m.radio.borrow_mut().tx.drain(..).collect();
        for f in out {
            if f.channel == CHANNEL {
                hw.deliver(&radio, &f.data, FREQ).unwrap();
                sent_by_rabbit += 1;
            }
        }
        // hostapd's frames, to the rabbit when it listens there; the
        // stick acknowledges what is for it.
        while let Some(s) = hw.sent().unwrap() {
            // hwsim knows its radio by the address it sends from (its
            // second one), not the permanent one.
            radio = s.transmitter;
            let to_rabbit = s.frame.get(4..10) == Some(&DEFAULT_MAC[..]);
            let group = s.frame.get(4).is_some_and(|b| b & 1 != 0);
            let mut r = m.radio.borrow_mut();
            let listening = r.rx_enabled && r.channel == CHANNEL;
            if listening && (to_rabbit || group) {
                r.rx.push_back(RxFrame::new(s.frame.clone()));
                heard_by_rabbit += 1;
            }
            drop(r);
            hw.status(&s, listening && to_rabbit).unwrap();
        }
    }
    let console = m.console();
    eprintln!(
        "{sent_by_rabbit} frames to hostapd, {heard_by_rabbit} from it, {} ms",
        m.soc.millis()
    );
    assert!(
        console.contains(&expect),
        "never ran the served bytecode:\n{console}"
    );
    assert_eq!(m.events, [], "no reset");
    // What the stick could not decrypt: [none, ICV, MIC, no key]. On
    // WPA3 it holds no key, by design, and the firmware opens the frames.
    let errors = m.radio.borrow().rx_cipher_errors;
    eprintln!("cipher errors at the stick: {errors:?}");
    assert_eq!(errors[1..3], [0, 0], "frames that failed to decrypt");
}
