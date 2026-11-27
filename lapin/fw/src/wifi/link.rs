//! The station of `lapin_core::wifi` on the real stick.

use lapin_core::rng::Pool;
use lapin_core::wifi::{HwCipher, Link, Mac, Rx, Tx};

use super::rt2573::{Cipher, Rate, Stick, TxOptions};
use crate::{sync::Shared, timer, watchdog};

/// How long a frame may wait for the previous one to leave.
const TX_WAIT_MS: u32 = 50;

pub struct Radio<'a> {
    pub stick: &'a mut Stick,
    pub pool: &'a mut Pool,
}

/// Frames that could not be handed to the stick in time.
pub static TX_LOST: Shared<u32> = Shared::new(0);

fn rate(n: u8) -> Rate {
    match n {
        1 => Rate::Mbps2,
        2 => Rate::Mbps5_5,
        3 => Rate::Mbps11,
        4 => Rate::Mbps6,
        5 => Rate::Mbps9,
        6 => Rate::Mbps12,
        7 => Rate::Mbps18,
        8 => Rate::Mbps24,
        9 => Rate::Mbps36,
        10 => Rate::Mbps48,
        11 => Rate::Mbps54,
        _ => Rate::Mbps1,
    }
}

fn cipher(c: HwCipher) -> Cipher {
    match c {
        HwCipher::None => Cipher::None,
        HwCipher::Wep40 => Cipher::Wep40,
        HwCipher::Wep104 => Cipher::Wep104,
        HwCipher::Tkip => Cipher::Tkip,
        HwCipher::Ccmp => Cipher::Ccmp,
    }
}

impl Link for Radio<'_> {
    fn mac(&self) -> Mac {
        self.stick.mac
    }

    fn millis(&self) -> u32 {
        timer::millis()
    }

    fn transmit(&mut self, frame: &[u8], tx: &Tx) -> bool {
        let options = TxOptions {
            rate: rate(tx.rate),
            ack: tx.ack,
            cipher: cipher(tx.cipher),
            key_index: tx.key,
            iv: tx.iv,
            eiv: tx.eiv,
            timestamp: tx.timestamp,
        };
        let start = timer::millis();
        loop {
            if self.stick.transmit(frame, &options) {
                return true;
            }
            watchdog::feed();
            if timer::millis().wrapping_sub(start) > TX_WAIT_MS {
                TX_LOST.set(TX_LOST.get() + 1);
                return false;
            }
        }
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Option<Rx> {
        let got = self.stick.receive(buffer)?;
        // Arrival time, strength and the first bytes: what an onlooker
        // cannot know exactly.
        let mut x = timer::millis() ^ (got.rssi as u32) << 24 ^ (got.len as u32) << 12;
        for w in buffer[..got.len.min(32)].as_chunks::<4>().0 {
            x = x.rotate_left(5) ^ u32::from_le_bytes(*w);
        }
        self.pool.mix(x);
        Some(Rx {
            len: got.len,
            rssi: got.rssi,
            decrypted: got.decrypted,
        })
    }

    fn set_channel(&mut self, channel: u8) {
        let _ = self.stick.set_channel(channel);
    }

    fn set_bssid(&mut self, bssid: &Mac) {
        let _ = self.stick.set_bssid(bssid);
    }

    fn set_key(&mut self, index: u8, c: HwCipher, key: &[u8], tx_mic: &[u8; 8], rx_mic: &[u8; 8]) {
        let _ = self.stick.set_key(index, cipher(c), key, tx_mic, rx_mic);
    }

    fn set_beacon(&mut self, frame: Option<&[u8]>) {
        let _ = self.stick.set_beacon(frame);
    }

    fn set_answer_rates(&mut self, mask: u16) {
        let _ = self.stick.set_answer_rates(mask);
    }

    fn pause(&mut self) {
        watchdog::feed();
    }

    fn random(&mut self, out: &mut [u8]) {
        self.pool.stir(&[&timer::millis().to_le_bytes()]);
        self.pool.fill(out);
    }
}
