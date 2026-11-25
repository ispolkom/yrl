//! Frames of a tunnel (a TCP connection made by the server on behalf of the client).
//! OPEN `[id u64][port u16][host_len u8][host]` exact (client -> server); READY `[id]` (server -> client);
//! DATA `[id][bytes]` both ways; EOF `[id]` = no more bytes from this side (both ways); CLOSE `[id]` = finished or aborted (both ways).
use crate::wire::{with_id, WireError};

pub const TUN_OPEN: u8 = 30;
pub const TUN_READY: u8 = 31;
pub const TUN_DATA: u8 = 32;
pub const TUN_EOF: u8 = 33;
pub const TUN_CLOSE: u8 = 34;

pub const MAX_HOST: usize = 255;
pub const CHUNK: usize = 32 * 1024;

pub const E_DENIED: u16 = 14;
pub const E_CONNECT: u16 = 15;

/// a host is a name or an address: printable ASCII without spaces (international names arrive in their punycode form)
pub fn host_ok(h: &str) -> bool {
    !h.is_empty() && h.len() <= MAX_HOST && h.bytes().all(|c| c.is_ascii_graphic())
}

pub fn encode_open(id: u64, host: &str, port: u16) -> Result<Vec<u8>, WireError> {
    if !host_ok(host) || port == 0 {
        return Err(WireError::TooLarge);
    }
    let mut v = with_id(id, &port.to_be_bytes());
    v.push(host.len() as u8);
    v.extend_from_slice(host.as_bytes());
    Ok(v)
}

pub fn decode_open(b: &[u8]) -> Result<(u64, String, u16), WireError> {
    if b.len() < 11 {
        return Err(WireError::Short);
    }
    let n = b[10] as usize;
    if b.len() != 11 + n {
        return Err(WireError::Malformed);
    }
    let host = std::str::from_utf8(&b[11..]).map_err(|_| WireError::Malformed)?;
    let port = u16::from_be_bytes([b[8], b[9]]);
    if !host_ok(host) || port == 0 {
        return Err(WireError::Malformed);
    }
    Ok((u64::from_be_bytes(b[..8].try_into().unwrap()), host.to_string(), port))
}
