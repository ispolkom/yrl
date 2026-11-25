//! Frames inside the encrypted channel: `[kind u8][stream u32][payload]`. Parsing is bounded: nothing is allocated from a declared length before it is checked.
pub const MAX_FRAME: usize = 65_519;
pub const MAX_ARGS: usize = 256;
pub const MAX_ARG_LEN: usize = 4096;

pub const PING: u8 = 0;
pub const PONG: u8 = 1;
pub const EXEC_REQ: u8 = 2;
pub const STDOUT: u8 = 3;
pub const STDERR: u8 = 4;
pub const EXIT: u8 = 5;
pub const ERROR: u8 = 6;
pub const CLOSE: u8 = 7;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub stream: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    Short,
    TooLarge,
    Malformed,
}

impl Frame {
    pub fn new(kind: u8, stream: u32, payload: Vec<u8>) -> Frame {
        Frame { kind, stream, payload }
    }
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if 5 + self.payload.len() > MAX_FRAME {
            return Err(WireError::TooLarge);
        }
        let mut v = Vec::with_capacity(5 + self.payload.len());
        v.push(self.kind);
        v.extend_from_slice(&self.stream.to_be_bytes());
        v.extend_from_slice(&self.payload);
        Ok(v)
    }
    pub fn decode(b: &[u8]) -> Result<Frame, WireError> {
        if b.len() < 5 {
            return Err(WireError::Short);
        }
        if b.len() > MAX_FRAME {
            return Err(WireError::TooLarge);
        }
        Ok(Frame { kind: b[0], stream: u32::from_be_bytes(b[1..5].try_into().unwrap()), payload: b[5..].to_vec() })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecReq {
    pub request_id: u64,
    pub timeout_ms: u32,
    pub argv: Vec<Vec<u8>>,
}

impl ExecReq {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.argv.is_empty() || self.argv.len() > MAX_ARGS || self.argv.iter().any(|a| a.len() > MAX_ARG_LEN) {
            return Err(WireError::TooLarge);
        }
        let mut v = Vec::new();
        v.extend_from_slice(&self.request_id.to_be_bytes());
        v.extend_from_slice(&self.timeout_ms.to_be_bytes());
        v.extend_from_slice(&(self.argv.len() as u16).to_be_bytes());
        for a in &self.argv {
            v.extend_from_slice(&(a.len() as u16).to_be_bytes());
            v.extend_from_slice(a);
        }
        if 5 + v.len() > MAX_FRAME {
            return Err(WireError::TooLarge);
        }
        Ok(v)
    }
    pub fn decode(b: &[u8]) -> Result<ExecReq, WireError> {
        if b.len() < 14 {
            return Err(WireError::Short);
        }
        let request_id = u64::from_be_bytes(b[0..8].try_into().unwrap());
        let timeout_ms = u32::from_be_bytes(b[8..12].try_into().unwrap());
        let argc = u16::from_be_bytes(b[12..14].try_into().unwrap()) as usize;
        if argc == 0 || argc > MAX_ARGS {
            return Err(WireError::TooLarge);
        }
        let mut at = 14;
        let mut argv = Vec::with_capacity(argc.min(16));
        for _ in 0..argc {
            if b.len() < at + 2 {
                return Err(WireError::Short);
            }
            let n = u16::from_be_bytes(b[at..at + 2].try_into().unwrap()) as usize;
            at += 2;
            if n > MAX_ARG_LEN {
                return Err(WireError::TooLarge);
            }
            if b.len() < at + n {
                return Err(WireError::Short);
            }
            argv.push(b[at..at + n].to_vec());
            at += n;
        }
        if at != b.len() {
            return Err(WireError::Malformed);
        }
        Ok(ExecReq { request_id, timeout_ms, argv })
    }
}

/// `[request_id u64][rest]` used by STDOUT, STDERR, EXIT, ERROR
pub fn with_id(request_id: u64, rest: &[u8]) -> Vec<u8> {
    let mut v = request_id.to_be_bytes().to_vec();
    v.extend_from_slice(rest);
    v
}

pub fn split_id(p: &[u8]) -> Result<(u64, &[u8]), WireError> {
    if p.len() < 8 {
        return Err(WireError::Short);
    }
    Ok((u64::from_be_bytes(p[..8].try_into().unwrap()), &p[8..]))
}

pub const LOGIN: u8 = 8;
pub const LOGIN_OK: u8 = 9;
pub const LOGIN_FAIL: u8 = 10;
pub const MAX_LOGIN: usize = 64;
pub const MAX_PASSWORD: usize = 256;

/// `[login_len u8][login][password_len u16][password]`; both bounded, nothing trailing.
pub fn encode_login(login: &[u8], password: &[u8]) -> Result<Vec<u8>, WireError> {
    if login.is_empty() || login.len() > MAX_LOGIN || password.len() > MAX_PASSWORD {
        return Err(WireError::TooLarge);
    }
    let mut v = vec![login.len() as u8];
    v.extend_from_slice(login);
    v.extend_from_slice(&(password.len() as u16).to_be_bytes());
    v.extend_from_slice(password);
    Ok(v)
}

pub fn decode_login(b: &[u8]) -> Result<(&[u8], &[u8]), WireError> {
    let n = *b.first().ok_or(WireError::Short)? as usize;
    if n == 0 || n > MAX_LOGIN {
        return Err(WireError::TooLarge);
    }
    if b.len() < 1 + n + 2 {
        return Err(WireError::Short);
    }
    let login = &b[1..1 + n];
    let m = u16::from_be_bytes(b[1 + n..3 + n].try_into().unwrap()) as usize;
    if m > MAX_PASSWORD {
        return Err(WireError::TooLarge);
    }
    if b.len() != 3 + n + m {
        return Err(WireError::Malformed);
    }
    Ok((login, &b[3 + n..]))
}

pub const PTY_OPEN: u8 = 11;
pub const PTY_IN: u8 = 12;
pub const PTY_OUT: u8 = 13;
pub const PTY_RESIZE: u8 = 14;
pub const PTY_EXIT: u8 = 15;
pub const PTY_CLOSE: u8 = 16;
pub const MAX_TERM: usize = 32;
pub const MAX_DIM: u16 = 1000;

/// `[id u64][rows u16][cols u16][term_len u8][term]`, exact; 1 <= rows, cols <= MAX_DIM
pub fn encode_pty_open(id: u64, rows: u16, cols: u16, term: &[u8]) -> Result<Vec<u8>, WireError> {
    if term.len() > MAX_TERM || !(1..=MAX_DIM).contains(&rows) || !(1..=MAX_DIM).contains(&cols) {
        return Err(WireError::TooLarge);
    }
    let mut v = with_id(id, &rows.to_be_bytes());
    v.extend_from_slice(&cols.to_be_bytes());
    v.push(term.len() as u8);
    v.extend_from_slice(term);
    Ok(v)
}

pub fn decode_pty_open(b: &[u8]) -> Result<(u64, u16, u16, &[u8]), WireError> {
    if b.len() < 13 {
        return Err(WireError::Short);
    }
    let id = u64::from_be_bytes(b[..8].try_into().unwrap());
    let (rows, cols, n) = (u16::from_be_bytes([b[8], b[9]]), u16::from_be_bytes([b[10], b[11]]), b[12] as usize);
    if n > MAX_TERM || !(1..=MAX_DIM).contains(&rows) || !(1..=MAX_DIM).contains(&cols) {
        return Err(WireError::TooLarge);
    }
    if b.len() != 13 + n {
        return Err(WireError::Malformed);
    }
    Ok((id, rows, cols, &b[13..]))
}

/// `[id u64][rows u16][cols u16]`, exact
pub fn encode_resize(id: u64, rows: u16, cols: u16) -> Vec<u8> {
    let mut v = with_id(id, &rows.to_be_bytes());
    v.extend_from_slice(&cols.to_be_bytes());
    v
}

pub fn decode_resize(b: &[u8]) -> Result<(u64, u16, u16), WireError> {
    if b.len() != 12 {
        return Err(if b.len() < 12 { WireError::Short } else { WireError::Malformed });
    }
    let (rows, cols) = (u16::from_be_bytes([b[8], b[9]]), u16::from_be_bytes([b[10], b[11]]));
    if !(1..=MAX_DIM).contains(&rows) || !(1..=MAX_DIM).contains(&cols) {
        return Err(WireError::TooLarge);
    }
    Ok((u64::from_be_bytes(b[..8].try_into().unwrap()), rows, cols))
}
