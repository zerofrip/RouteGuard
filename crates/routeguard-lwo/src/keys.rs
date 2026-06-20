//! Parse WG keys from `.conf` for LWO obfuscation.

use base64::Engine;
use routeguard_core::error::{Result, RouteGuardError};
use x25519_dalek::{PublicKey, StaticSecret};

const KEY_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct LwoKeys {
    pub client_public: [u8; KEY_LEN],
    pub server_public: [u8; KEY_LEN],
}

pub fn parse_lwo_keys(conf_text: &str) -> Result<LwoKeys> {
    let mut private_key: Option<[u8; KEY_LEN]> = None;
    let mut peer_public: Option<[u8; KEY_LEN]> = None;
    let mut section = "";

    for line in conf_text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();

        match section.to_ascii_lowercase().as_str() {
            "interface" if key == "privatekey" => {
                private_key = Some(decode_key(val)?);
            }
            "peer" if key == "publickey" => {
                peer_public = Some(decode_key(val)?);
            }
            _ => {}
        }
    }

    let private = private_key
        .ok_or_else(|| RouteGuardError::Config("LWO requires Interface PrivateKey".into()))?;
    let server =
        peer_public.ok_or_else(|| RouteGuardError::Config("LWO requires Peer PublicKey".into()))?;

    let client_public = derive_public_key(&private);

    Ok(LwoKeys {
        client_public,
        server_public: server,
    })
}

fn decode_key(s: &str) -> Result<[u8; KEY_LEN]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| RouteGuardError::Config(format!("invalid base64 key: {e}")))?;
    if bytes.len() != KEY_LEN {
        return Err(RouteGuardError::Config(format!(
            "key must be {KEY_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn derive_public_key(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let secret = StaticSecret::from(*private);
    PublicKey::from(&secret).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keys_from_conf() {
        let conf = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n[Peer]\nPublicKey = 8Ka2l4T0tVrSR5pkcsvRG++mBlxfuf8XOxpqBkOCikU=\nEndpoint = 1.2.3.4:51820\n";
        let keys = parse_lwo_keys(conf).unwrap();
        assert_ne!(keys.client_public, [0u8; 32]);
        assert_ne!(keys.server_public, [0u8; 32]);
    }
}
