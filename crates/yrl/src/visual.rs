//! The visual mode: a mouse-and-keyboard file browser for the remote machine, drawn in the terminal.
//! This file is the whole logic and has no input/output of its own: `InputParser` turns terminal bytes into events, `App` turns events into
//! commands and a picture (`render`), so everything can be tested without a terminal. The runner (src/bin/yrl.rs) connects it to the real terminal and the client.
//!
//! One rule above all: whatever comes from the other machine (file names, error texts, paths) is data, never terminal commands. `sanitize` removes every
//! control character, so a file named like an escape sequence cannot move the cursor, set the window title, or rewrite the screen.
use crate::fsops::{DirEntry, Kind};
use std::path::PathBuf;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- text safety and formatting

/// a name or a message as it may be shown: no control characters (C0, DEL, C1), no bidirectional overrides, no invisible formatting characters
pub fn sanitize(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .chars()
        .map(|c| match c {
            '\u{FFFD}' => '?',
            c if c.is_control() => '?',
            '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}' | '\u{061C}' => '?',
            c => c,
        })
        .collect()
}

pub fn join(cwd: &[u8], name: &[u8]) -> Vec<u8> {
    let mut v = cwd.to_vec();
    if !v.ends_with(b"/") {
        v.push(b'/');
    }
    v.extend_from_slice(name);
    v
}

pub fn parent(cwd: &[u8]) -> Vec<u8> {
    let trimmed = if cwd.len() > 1 { cwd.strip_suffix(b"/").unwrap_or(cwd) } else { cwd };
    match trimmed.iter().rposition(|c| *c == b'/') {
        Some(0) | None => b"/".to_vec(),
        Some(i) => trimmed[..i].to_vec(),
    }
}

/// a name typed by the user for something new in the current directory: one component, nothing special
pub fn valid_new_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 255 && n != "." && n != ".." && !n.contains('/') && !n.contains('\0') && !n.chars().any(|c| c.is_control())
}

pub fn human_size(n: u64) -> String {
    const U: [&str; 5] = ["B", "K", "M", "G", "T"];
    let (mut v, mut i) = (n as f64, 0);
    while v >= 1024.0 && i < 4 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n}B") } else { format!("{v:.1}{}", U[i]) }
}

/// "2026-10-05 14:03" (UTC)
pub fn fmt_time(t: i64) -> String {
    let (days, secs) = (t.div_euclid(86400), t.rem_euclid(86400));
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", secs / 3600, (secs % 3600) / 60)
}

pub fn fmt_mode(kind: Kind, mode: u16) -> String {
    let t = match kind {
        Kind::File => '-',
        Kind::Dir => 'd',
        Kind::Symlink => 'l',
        Kind::Other => '?',
    };
    let mut s = String::from(t);
    for sh in [6, 3, 0] {
        let b = (mode >> sh) & 7;
        s.push(if b & 4 != 0 { 'r' } else { '-' });
        s.push(if b & 2 != 0 { 'w' } else { '-' });
        s.push(if b & 1 != 0 { 'x' } else { '-' });
    }
    s
}

/// exactly `w` characters: cut or padded
fn fit(s: &str, w: usize) -> String {
    let mut out: String = s.chars().take(w).collect();
    let n = out.chars().count();
    out.extend(std::iter::repeat_n(' ', w - n));
    out
}

// ---------------------------------------------------------------- input

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
    Enter,
    Backspace,
    Delete,
    Esc,
    Tab,
    Char(char),
    Ctrl(char),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseKind {
    Press,
    Release,
    Wheel(i8),
    Drag,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mouse {
    pub kind: MouseKind,
    /// 0 = left; only the left button does anything
    pub button: u8,
    pub row: u16,
    pub col: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    Key(Key),
    Mouse(Mouse),
    Resize(u16, u16),
}

#[derive(Default)]
pub struct InputParser {
    buf: Vec<u8>,
}

const MAX_SEQ: usize = 48;

impl InputParser {
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Input> {
        self.buf.extend_from_slice(bytes);
        let mut out = vec![];
        loop {
            match self.next() {
                Some(Some(i)) => out.push(i),
                Some(None) => {}
                None => break,
            }
        }
        out
    }

    /// a lone ESC that nothing followed for a while is the Escape key
    pub fn flush_pending(&mut self) -> Option<Input> {
        if self.buf == [0x1b] {
            self.buf.clear();
            return Some(Input::Key(Key::Esc));
        }
        None
    }

    /// None = need more bytes; Some(None) = something consumed that means nothing; Some(Some(i)) = an event
    fn next(&mut self) -> Option<Option<Input>> {
        let b = &self.buf;
        let first = *b.first()?;
        let take = |s: &mut Self, n: usize| {
            s.buf.drain(..n);
        };
        match first {
            0x1b => {
                if b.len() < 2 {
                    return None;
                }
                match b[1] {
                    b'[' => {
                        // CSI: parameters, then a final byte 0x40..=0x7E
                        let end = b[2..].iter().position(|c| (0x40..=0x7E).contains(c));
                        let Some(e) = end else {
                            if b.len() > MAX_SEQ {
                                self.buf.clear(); // garbage that never ends
                                return Some(None);
                            }
                            return None;
                        };
                        let fin = b[2 + e];
                        let params = String::from_utf8_lossy(&b[2..2 + e]).into_owned();
                        let total = 3 + e;
                        if fin == b'M' && params.is_empty() {
                            // the old mouse format: three more bytes follow; we do not use it
                            if b.len() < total + 3 {
                                return None;
                            }
                            take(self, total + 3);
                            return Some(None);
                        }
                        take(self, total);
                        Some(csi(&params, fin))
                    }
                    b'O' => {
                        if b.len() < 3 {
                            return None;
                        }
                        let k = match b[2] {
                            b'A' => Some(Key::Up),
                            b'B' => Some(Key::Down),
                            b'C' => Some(Key::Right),
                            b'D' => Some(Key::Left),
                            b'H' => Some(Key::Home),
                            b'F' => Some(Key::End),
                            _ => None,
                        };
                        take(self, 3);
                        Some(k.map(Input::Key))
                    }
                    _ => {
                        take(self, 1); // Alt+key and the like: the escape is dropped, the key is read on its own
                        Some(None)
                    }
                }
            }
            0x0d | 0x0a => {
                take(self, 1);
                Some(Some(Input::Key(Key::Enter)))
            }
            0x7f | 0x08 => {
                take(self, 1);
                Some(Some(Input::Key(Key::Backspace)))
            }
            0x09 => {
                take(self, 1);
                Some(Some(Input::Key(Key::Tab)))
            }
            c @ 0x01..=0x1a => {
                take(self, 1);
                Some(Some(Input::Key(Key::Ctrl((b'a' + c - 1) as char))))
            }
            0x00 | 0x1c..=0x1f => {
                take(self, 1);
                Some(None)
            }
            c => {
                let need = if c < 0x80 { 1 } else if c >> 5 == 0b110 { 2 } else if c >> 4 == 0b1110 { 3 } else if c >> 3 == 0b11110 { 4 } else { 0 };
                if need == 0 {
                    take(self, 1); // a stray continuation byte
                    return Some(None);
                }
                if b.len() < need {
                    return None;
                }
                let ch = std::str::from_utf8(&b[..need]).ok().and_then(|s| s.chars().next());
                take(self, if ch.is_some() { need } else { 1 });
                Some(ch.map(|c| Input::Key(Key::Char(c))))
            }
        }
    }
}

fn csi(params: &str, fin: u8) -> Option<Input> {
    if let Some(rest) = params.strip_prefix('<') {
        // SGR mouse: <button;column;row  M (press/move) or m (release)
        let v: Vec<u64> = rest.split(';').map(|p| p.parse::<u64>().unwrap_or(u64::MAX)).collect();
        if v.len() != 3 || !(fin == b'M' || fin == b'm') || v[0] > 255 {
            return None;
        }
        let (b, x, y) = (v[0] as u32, v[1].saturating_sub(1).min(u16::MAX as u64) as u16, v[2].saturating_sub(1).min(u16::MAX as u64) as u16);
        let kind = if b & 64 != 0 {
            MouseKind::Wheel(if b & 1 == 0 { -1 } else { 1 })
        } else if b & 32 != 0 {
            MouseKind::Drag
        } else if fin == b'm' {
            MouseKind::Release
        } else {
            MouseKind::Press
        };
        return Some(Input::Mouse(Mouse { kind, button: (b & 3) as u8, row: y, col: x }));
    }
    let n: Option<u32> = params.split(';').next().and_then(|p| p.parse().ok());
    let k = match fin {
        b'A' => Key::Up,
        b'B' => Key::Down,
        b'C' => Key::Right,
        b'D' => Key::Left,
        b'H' => Key::Home,
        b'F' => Key::End,
        b'~' => match n? {
            1 | 7 => Key::Home,
            4 | 8 => Key::End,
            3 => Key::Delete,
            5 => Key::PageUp,
            6 => Key::PageDown,
            _ => return None,
        },
        _ => return None,
    };
    Some(Input::Key(k))
}

// ---------------------------------------------------------------- the application

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmd {
    /// show this directory (the runner resolves it to a canonical path first)
    List(Vec<u8>),
    Download { remote: Vec<u8>, local: PathBuf },
    Upload { local: PathBuf, remote: Vec<u8> },
    Mkdir(Vec<u8>),
    Remove(Vec<u8>),
    Rename { from: Vec<u8>, to: Vec<u8> },
    Quit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Header,
    Titles,
    Normal,
    Dir,
    Selected,
    Status,
    Error,
    Bar,
    Prompt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub text: String,
    pub style: Style,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Prompt {
    Mkdir,
    Rename(Vec<u8>),
    Upload,
    Goto,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Mode {
    Browse,
    Prompt { kind: Prompt, text: Vec<char>, at: usize },
    Confirm { name: Vec<u8> },
    Help,
}

pub struct App {
    pub cwd: Vec<u8>,
    entries: Vec<DirEntry>,
    sel: usize,
    top: usize,
    pub rows: u16,
    pub cols: u16,
    status: Option<(String, bool)>,
    mode: Mode,
    last_click: Option<(Instant, usize)>,
    /// downloads go here
    pub local_dir: PathBuf,
    select_name: Option<Vec<u8>>,
}

const DOUBLE_CLICK: Duration = Duration::from_millis(450);
const MAX_PROMPT: usize = 4096;

const BAR: [(&str, char, &str); 9] = [("d", 'd', "down"), ("u", 'u', "up"), ("m", 'm', "mkdir"), ("r", 'r', "rename"), ("x", 'x', "del"), ("g", 'g', "goto"), ("F5", 'R', "reload"), ("?", '?', "help"), ("q", 'q', "quit")];

impl App {
    pub fn new(start: Vec<u8>, rows: u16, cols: u16, local_dir: PathBuf) -> App {
        App { cwd: start, entries: vec![], sel: 0, top: 0, rows, cols, status: None, mode: Mode::Browse, last_click: None, local_dir, select_name: None }
    }

    fn has_parent(&self) -> bool {
        self.cwd != b"/"
    }
    fn count(&self) -> usize {
        self.entries.len() + self.has_parent() as usize
    }
    fn list_h(&self) -> usize {
        (self.rows as usize).saturating_sub(4)
    }
    fn entry_at(&self, i: usize) -> Option<&DirEntry> {
        let off = self.has_parent() as usize;
        if i < off { None } else { self.entries.get(i - off) }
    }
    pub fn selected_name(&self) -> Option<Vec<u8>> {
        self.entry_at(self.sel).map(|e| e.name.clone())
    }

    pub fn error(&mut self, msg: &str) {
        self.status = Some((sanitize(msg.as_bytes()), true));
    }
    pub fn note(&mut self, msg: &str) {
        self.status = Some((sanitize(msg.as_bytes()), false));
    }

    /// a listing arrived for `path`
    pub fn set_listing(&mut self, path: Vec<u8>, mut entries: Vec<DirEntry>) {
        entries.sort_by(|a, b| (a.kind != Kind::Dir).cmp(&(b.kind != Kind::Dir)).then_with(|| sanitize(&a.name).to_lowercase().cmp(&sanitize(&b.name).to_lowercase())).then_with(|| a.name.cmp(&b.name)));
        // names come from the other machine: a name that is not one plain component could point a download anywhere on THIS machine
        entries.retain(|e| !e.name.is_empty() && e.name != b"." && e.name != b".." && !e.name.contains(&b'/') && !e.name.contains(&0));
        self.cwd = path;
        self.entries = entries;
        self.sel = 0;
        if let Some(n) = self.select_name.take() {
            if let Some(i) = self.entries.iter().position(|e| e.name == n) {
                self.sel = i + self.has_parent() as usize;
            }
        }
        self.top = 0;
        self.keep_selection_visible();
        // an open prompt or confirmation stays: a listing that arrives meanwhile (a refresh after an operation) must not cancel what the user is typing
    }

    fn keep_selection_visible(&mut self) {
        let n = self.count();
        if n == 0 {
            self.sel = 0;
            self.top = 0;
            return;
        }
        self.sel = self.sel.min(n - 1);
        let h = self.list_h().max(1);
        if self.sel < self.top {
            self.top = self.sel;
        }
        if self.sel >= self.top + h {
            self.top = self.sel + 1 - h;
        }
        self.top = self.top.min(n.saturating_sub(1));
    }

    fn move_to(&mut self, i: isize) {
        let n = self.count() as isize;
        self.sel = if n == 0 { 0 } else { i.clamp(0, n - 1) as usize };
        self.keep_selection_visible();
    }

    pub fn handle(&mut self, input: Input, now: Instant) -> Vec<Cmd> {
        match input {
            Input::Resize(r, c) => {
                self.rows = r.max(1);
                self.cols = c.max(1);
                self.keep_selection_visible();
                vec![]
            }
            Input::Key(k) => self.key(k),
            Input::Mouse(m) => self.mouse(m, now),
        }
    }

    fn open_selected(&mut self) -> Vec<Cmd> {
        if self.sel == 0 && self.has_parent() {
            self.select_name = self.cwd.rsplit(|c| *c == b'/').next().map(|n| n.to_vec());
            return vec![Cmd::List(parent(&self.cwd))];
        }
        match self.entry_at(self.sel).cloned() {
            Some(e) if e.kind == Kind::Dir || e.kind == Kind::Symlink => vec![Cmd::List(join(&self.cwd, &e.name))],
            Some(e) => {
                let s = format!("{}  {}  {}", sanitize(&e.name), human_size(e.size), fmt_time(e.mtime));
                self.note(&s);
                vec![]
            }
            None => vec![],
        }
    }

    fn key(&mut self, k: Key) -> Vec<Cmd> {
        match &mut self.mode {
            Mode::Help => {
                self.mode = Mode::Browse;
                vec![]
            }
            Mode::Confirm { name } => {
                let name = name.clone();
                self.mode = Mode::Browse;
                if matches!(k, Key::Char('y') | Key::Char('Y')) {
                    self.note("deleting...");
                    return vec![Cmd::Remove(join(&self.cwd, &name))];
                }
                self.note("not deleted");
                vec![]
            }
            Mode::Prompt { .. } => self.prompt_key(k),
            Mode::Browse => self.browse_key(k),
        }
    }

    fn browse_key(&mut self, k: Key) -> Vec<Cmd> {
        let page = self.list_h().max(1) as isize;
        let sel = self.sel as isize;
        match k {
            Key::Up | Key::Char('k') => self.move_to(sel - 1),
            Key::Down | Key::Char('j') => self.move_to(sel + 1),
            Key::PageUp => self.move_to(sel - page),
            Key::PageDown => self.move_to(sel + page),
            Key::Home => self.move_to(0),
            Key::End => self.move_to(isize::MAX / 2),
            Key::Enter | Key::Right | Key::Char('l') => return self.open_selected(),
            Key::Backspace | Key::Left | Key::Char('h') => {
                if self.has_parent() {
                    self.select_name = self.cwd.rsplit(|c| *c == b'/').next().map(|n| n.to_vec());
                    return vec![Cmd::List(parent(&self.cwd))];
                }
            }
            Key::Char('R') | Key::Ctrl('l') => {
                if self.select_name.is_none() {
                    self.select_name = self.selected_name(); // a rename has already said which name to land on
                }
                return vec![Cmd::List(self.cwd.clone())];
            }
            Key::Char('~') => return vec![Cmd::List(b".".to_vec())],
            Key::Char('q') | Key::Ctrl('c') | Key::Esc => return vec![Cmd::Quit],
            Key::Char('?') => self.mode = Mode::Help,
            Key::Char('d') => match self.entry_at(self.sel).cloned() {
                Some(e) if e.kind == Kind::File => {
                    self.note(&format!("downloading {} ...", sanitize(&e.name)));
                    return vec![Cmd::Download { remote: join(&self.cwd, &e.name), local: self.local_dir.join(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(&e.name)) }];
                }
                Some(_) => self.error("only files can be downloaded here"),
                None => {}
            },
            Key::Char('u') => self.mode = Mode::Prompt { kind: Prompt::Upload, text: vec![], at: 0 },
            Key::Char('m') => self.mode = Mode::Prompt { kind: Prompt::Mkdir, text: vec![], at: 0 },
            Key::Char('g') => self.mode = Mode::Prompt { kind: Prompt::Goto, text: vec![], at: 0 },
            Key::Char('r') | Key::Char('F') => {
                if let Some(e) = self.entry_at(self.sel) {
                    let text: Vec<char> = sanitize(&e.name).chars().collect();
                    let at = text.len();
                    let old = e.name.clone();
                    self.mode = Mode::Prompt { kind: Prompt::Rename(old), text, at };
                }
            }
            Key::Char('x') | Key::Delete => {
                if let Some(e) = self.entry_at(self.sel) {
                    self.mode = Mode::Confirm { name: e.name.clone() };
                }
            }
            _ => {}
        }
        vec![]
    }

    fn prompt_key(&mut self, k: Key) -> Vec<Cmd> {
        let Mode::Prompt { kind, text, at } = &mut self.mode else { return vec![] };
        match k {
            Key::Esc | Key::Ctrl('c') => {
                self.mode = Mode::Browse;
            }
            Key::Char(c) if !c.is_control() => {
                if text.len() < MAX_PROMPT {
                    text.insert(*at, c);
                    *at += 1;
                }
            }
            Key::Backspace => {
                if *at > 0 {
                    *at -= 1;
                    text.remove(*at);
                }
            }
            Key::Delete => {
                if *at < text.len() {
                    text.remove(*at);
                }
            }
            Key::Left => *at = at.saturating_sub(1),
            Key::Right => *at = (*at + 1).min(text.len()),
            Key::Home | Key::Ctrl('a') => *at = 0,
            Key::End | Key::Ctrl('e') => *at = text.len(),
            Key::Ctrl('u') => {
                text.clear();
                *at = 0;
            }
            Key::Enter => {
                let (kind, typed) = (kind.clone(), text.iter().collect::<String>());
                return self.submit(kind, typed);
            }
            _ => {}
        }
        vec![]
    }

    fn submit(&mut self, kind: Prompt, typed: String) -> Vec<Cmd> {
        let bad = |s: &mut Self, m: &str| {
            s.error(m);
            vec![]
        };
        match kind {
            Prompt::Mkdir => {
                if !valid_new_name(&typed) {
                    return bad(self, "that is not a usable name (no slashes, not empty, not . or ..)");
                }
                self.mode = Mode::Browse;
                self.note("creating...");
                vec![Cmd::Mkdir(join(&self.cwd, typed.as_bytes()))]
            }
            Prompt::Rename(old) => {
                if !valid_new_name(&typed) {
                    return bad(self, "that is not a usable name (no slashes, not empty, not . or ..)");
                }
                self.mode = Mode::Browse;
                if typed.as_bytes() == old.as_slice() {
                    return vec![];
                }
                self.select_name = Some(typed.as_bytes().to_vec());
                self.note("renaming...");
                vec![Cmd::Rename { from: join(&self.cwd, &old), to: join(&self.cwd, typed.as_bytes()) }]
            }
            Prompt::Upload => {
                let local = PathBuf::from(&typed);
                let base = local.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                if typed.is_empty() || !valid_new_name(&base) {
                    return bad(self, "give the path of a local file");
                }
                self.mode = Mode::Browse;
                self.note(&format!("uploading {} ...", sanitize(base.as_bytes())));
                vec![Cmd::Upload { local, remote: join(&self.cwd, base.as_bytes()) }]
            }
            Prompt::Goto => {
                if typed.is_empty() || typed.contains('\0') {
                    return bad(self, "give a directory");
                }
                self.mode = Mode::Browse;
                let target = if typed.starts_with('/') { typed.into_bytes() } else { join(&self.cwd, typed.as_bytes()) };
                vec![Cmd::List(target)]
            }
        }
    }

    // ---- the button bar: (first column, last column, key)
    fn bar_items(&self) -> Vec<(usize, usize, Key)> {
        let mut x = 1;
        let mut v = vec![];
        for (k, c, label) in BAR {
            let w = k.chars().count() + 1 + label.chars().count();
            if x + w > self.cols as usize {
                break;
            }
            v.push((x, x + w - 1, Key::Char(c)));
            x += w + 2;
        }
        v
    }

    fn mouse(&mut self, m: Mouse, now: Instant) -> Vec<Cmd> {
        if !matches!(self.mode, Mode::Browse) {
            return vec![];
        }
        match m.kind {
            MouseKind::Wheel(d) => {
                let sel = self.sel as isize;
                self.move_to(sel + d as isize * 3);
            }
            MouseKind::Press if m.button == 0 => {
                let (row, col) = (m.row as usize, m.col as usize);
                if self.rows >= 4 && row == self.rows as usize - 1 {
                    if let Some((_, _, key)) = self.bar_items().into_iter().find(|(a, b, _)| col >= *a && col <= *b) {
                        return self.key(key);
                    }
                    return vec![];
                }
                let h = self.list_h();
                if row >= 2 && row < 2 + h {
                    let i = self.top + (row - 2);
                    if i < self.count() {
                        self.sel = i;
                        self.keep_selection_visible();
                        let double = self.last_click.is_some_and(|(t, j)| j == i && now.saturating_duration_since(t) <= DOUBLE_CLICK);
                        self.last_click = if double { None } else { Some((now, i)) };
                        if double {
                            return self.open_selected();
                        }
                    }
                }
            }
            _ => {}
        }
        vec![]
    }

    // ---- drawing

    pub fn render(&self) -> Vec<Line> {
        let (rows, cols) = (self.rows as usize, self.cols as usize);
        let mut out: Vec<Line> = vec![];
        let line = |t: String, s: Style| Line { text: fit(&t, cols), style: s };
        let blank = |s: Style| Line { text: " ".repeat(cols), style: s };
        if let Mode::Help = self.mode {
            let help = ["yrl visual - keys", "", " arrows, PgUp/PgDn, Home/End   move", " Enter / double click          open a directory", " Backspace / Left              up", " d  download   u  upload   m  mkdir", " r  rename      x  delete   g  go to a path", " F5 or R refresh   ~ home   q quit", " the mouse works on rows and on the buttons below", "", " any key closes this help"];
            for i in 0..rows {
                out.push(line(help.get(i).map(|s| s.to_string()).unwrap_or_default(), if i == 0 { Style::Header } else { Style::Normal }));
            }
            return out;
        }
        out.push(line(format!(" yrl visual   {}", sanitize(&self.cwd)), Style::Header));
        if rows >= 2 {
            let meta = cols >= 52;
            let t = if meta { format!(" {:<w$}  {:>8}  {:<16}  {}", "name", "size", "modified (UTC)", "mode", w = cols.saturating_sub(2 + 2 + 8 + 2 + 16 + 2 + 10)) } else { " name".to_string() };
            out.push(line(t, Style::Titles));
        }
        let h = self.list_h();
        for r in 0..h {
            let i = self.top + r;
            if i >= self.count() {
                out.push(blank(Style::Normal));
                continue;
            }
            let selected = i == self.sel;
            let (name, meta) = match self.entry_at(i) {
                None => ("../".to_string(), String::new()),
                Some(e) => {
                    let mut n = sanitize(&e.name);
                    n.push_str(match e.kind {
                        Kind::Dir => "/",
                        Kind::Symlink => "@",
                        Kind::Other => "?",
                        Kind::File => "",
                    });
                    (n, format!("  {:>8}  {}  {}", if e.kind == Kind::Dir { "-".to_string() } else { human_size(e.size) }, fmt_time(e.mtime), fmt_mode(e.kind, e.mode)))
                }
            };
            let text = if cols >= 52 {
                let w = cols.saturating_sub(1 + meta.chars().count());
                format!(" {}{}", fit(&name, w.saturating_sub(0)), meta)
            } else {
                format!(" {name}")
            };
            let is_dir = i == 0 && self.has_parent() || self.entry_at(i).is_some_and(|e| e.kind == Kind::Dir);
            out.push(line(text, if selected { Style::Selected } else if is_dir { Style::Dir } else { Style::Normal }));
        }
        // status or prompt
        if rows >= 3 {
            let (text, style) = match &self.mode {
                Mode::Prompt { kind, text, .. } => {
                    let label = match kind {
                        Prompt::Mkdir => "new directory name: ",
                        Prompt::Rename(_) => "new name: ",
                        Prompt::Upload => "local file to upload: ",
                        Prompt::Goto => "go to: ",
                    };
                    (format!(" {label}{}", text.iter().collect::<String>()), Style::Prompt)
                }
                Mode::Confirm { name } => (format!(" delete {} ? (y/N)", sanitize(name)), Style::Prompt),
                _ => match &self.status {
                    Some((m, true)) => (format!(" ! {m}"), Style::Error),
                    Some((m, false)) => (format!(" {m}"), Style::Status),
                    None => (format!(" {} entries", self.entries.len()), Style::Status),
                },
            };
            out.push(line(text, style));
        }
        if rows >= 4 {
            let mut bar = " ".repeat(cols);
            let mut chars: Vec<char> = bar.chars().collect();
            for ((a, _b, _), (k, _, label)) in self.bar_items().into_iter().zip(BAR) {
                for (j, c) in format!("{k}:{label}").chars().enumerate() {
                    if a + j < chars.len() {
                        chars[a + j] = c;
                    }
                }
            }
            bar = chars.into_iter().collect();
            out.push(Line { text: bar, style: Style::Bar });
        }
        out.truncate(rows);
        while out.len() < rows {
            out.push(blank(Style::Normal));
        }
        out
    }
}
