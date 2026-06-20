//! Mullvad-compatible LWO wire format (header XOR + OBFUSCATION_BIT).

use rand::RngCore;

type MessageType = u8;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

/// Bit set in the second byte of the WG header to enable LWO.
const OBFUSCATION_BIT: u8 = 0b1000_0000;

pub fn obfuscate(rng: &mut impl RngCore, packet: &mut [u8], key: &[u8; 32]) {
    let Some(header_bytes) = header_mut(packet, 0) else {
        return;
    };

    xor_bytes(header_bytes, key);

    let rand_byte = (rng.next_u32() % u8::MAX as u32) as u8;
    header_bytes[1] = rand_byte | OBFUSCATION_BIT;
}

pub fn deobfuscate(packet: &mut [u8], key: &[u8; 32]) {
    let Some(header_bytes) = header_mut(packet, key[0]) else {
        return;
    };

    xor_bytes(header_bytes, key);
    header_bytes[1] = 0;
}

fn header_mut(packet: &mut [u8], key_byte: u8) -> Option<&mut [u8]> {
    let &header_type = packet.first()?;
    match header_type ^ key_byte {
        HANDSHAKE_INIT => packet.get_mut(..HANDSHAKE_INIT_SZ),
        HANDSHAKE_RESP => packet.get_mut(..HANDSHAKE_RESP_SZ),
        COOKIE_REPLY => packet.get_mut(..COOKIE_REPLY_SZ),
        DATA => packet.get_mut(..DATA_OVERHEAD_SZ),
        _ => None,
    }
}

fn xor_bytes(data: &mut [u8], key: &[u8; 32]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn fake_packet() -> Vec<u8> {
        let mut packet = vec![0u8; DATA_OVERHEAD_SZ + 100];
        packet[0] = DATA;
        rand::rngs::StdRng::from_seed([1u8; 32]).fill_bytes(&mut packet[DATA_OVERHEAD_SZ..]);
        packet
    }

    #[test]
    fn obfuscation_roundtrip() {
        let key = [0xefu8; 32];
        let mut packet = fake_packet();
        let original = packet.clone();

        let mut rng = rand::rngs::StdRng::from_seed([2u8; 32]);
        obfuscate(&mut rng, &mut packet, &key);
        assert_ne!(packet, original);
        assert_eq!(packet[DATA_OVERHEAD_SZ..], original[DATA_OVERHEAD_SZ..]);

        deobfuscate(&mut packet, &key);
        assert_eq!(packet, original);
    }
}
