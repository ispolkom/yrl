//! Frames of a file transfer. Every field is bounded and every length is exact.
//! PUT  `[id][mode u16][size u64][blake3 32][path_len u16][path]`     (client -> server: send me this file)
//! GET  `[id][offset u64][path_len u16][path]`                        (client -> server: give me this file from offset)
//! DATA `[id][bytes]` both ways; READY `[id][u64]` (PUT: offset the server already has, GET: size of the file);
//! END  client -> server `[id]` no more data; server -> client for PUT `[id]` = stored and verified, for GET `[id][blake3 32]`; ABORT `[id]`.
use crate::wire::{with_id, WireError};

pub const FILE_PUT: u8 = 20;
pub const FILE_GET: u8 = 21;
pub const FILE_DATA: u8 = 22;
pub const FILE_READY: u8 = 23;
pub const FILE_END: u8 = 24;
pub const FILE_ABORT: u8 = 25;

pub const MAX_PATH: usize = 4096;
/// payload bytes per DATA frame (a frame holds at most 65519 bytes with its 5-byte header and the 8-byte id)
pub const CHUNK: usize = 60 * 1024;

// error codes carried in ERROR frames
pub const E_OPEN: u16 = 8;
pub const E_VERIFY: u16 = 9;
pub const E_TOO_BIG: u16 = 10;
pub const E_REQUEST: u16 = 11;
pub const E_OFFSET: u16 = 12;
pub const E_IO: u16 = 13;
pub const E_QUOTA: u16 = 14;
pub const E_NO_SPACE: u16 = 15;

#[derive(Debug, PartialEq, Eq)]
pub struct PutReq {
    pub id: u64,
    pub mode: u16,
    pub size: u64,
    pub hash: [u8; 32],
    pub path: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct GetReq {
    pub id: u64,
    pub offset: u64,
    pub path: Vec<u8>,
}

/// a path is bytes of a file name: not empty, not too long, no NUL
pub fn path_ok(p: &[u8]) -> bool {
    !p.is_empty() && p.len() <= MAX_PATH && !p.contains(&0)
}

impl PutReq {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if !path_ok(&self.path) {
            return Err(WireError::TooLarge);
        }
        let mut v = with_id(self.id, &self.mode.to_be_bytes());
        v.extend_from_slice(&self.size.to_be_bytes());
        v.extend_from_slice(&self.hash);
        v.extend_from_slice(&(self.path.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.path);
        Ok(v)
    }
    pub fn decode(b: &[u8]) -> Result<PutReq, WireError> {
        if b.len() < 52 {
            return Err(WireError::Short);
        }
        let n = u16::from_be_bytes([b[50], b[51]]) as usize;
        if n > MAX_PATH {
            return Err(WireError::TooLarge);
        }
        if b.len() != 52 + n {
            return Err(WireError::Malformed);
        }
        let path = b[52..].to_vec();
        if !path_ok(&path) {
            return Err(WireError::Malformed);
        }
        Ok(PutReq { id: u64::from_be_bytes(b[..8].try_into().unwrap()), mode: u16::from_be_bytes([b[8], b[9]]), size: u64::from_be_bytes(b[10..18].try_into().unwrap()), hash: b[18..50].try_into().unwrap(), path })
    }
}

impl GetReq {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if !path_ok(&self.path) {
            return Err(WireError::TooLarge);
        }
        let mut v = with_id(self.id, &self.offset.to_be_bytes());
        v.extend_from_slice(&(self.path.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.path);
        Ok(v)
    }
    pub fn decode(b: &[u8]) -> Result<GetReq, WireError> {
        if b.len() < 18 {
            return Err(WireError::Short);
        }
        let n = u16::from_be_bytes([b[16], b[17]]) as usize;
        if n > MAX_PATH {
            return Err(WireError::TooLarge);
        }
        if b.len() != 18 + n {
            return Err(WireError::Malformed);
        }
        let path = b[18..].to_vec();
        if !path_ok(&path) {
            return Err(WireError::Malformed);
        }
        Ok(GetReq { id: u64::from_be_bytes(b[..8].try_into().unwrap()), offset: u64::from_be_bytes(b[8..16].try_into().unwrap()), path })
    }
}
