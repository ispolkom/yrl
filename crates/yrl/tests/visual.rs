//! The visual mode's logic: input decoding, navigation, mouse, prompts, drawing, and above all that nothing from the other machine can act on this terminal.
use std::path::PathBuf;
use std::time::{Duration, Instant};
use yrl::fsops::{DirEntry, Kind};
use yrl::visual::*;

fn e(name: &[u8], kind: Kind, size: u64) -> DirEntry {
    DirEntry { name: name.to_vec(), kind, size, mtime: 1_760_000_000, mode: 0o644 }
}

fn app(rows: u16, cols: u16) -> App {
    let mut a = App::new(b"/home/u".to_vec(), rows, cols, PathBuf::from("/tmp/dl"));
    a.set_listing(b"/home/u".to_vec(), vec![e(b"zeta.txt", Kind::File, 10), e(b"Beta", Kind::Dir, 0), e(b"alpha", Kind::Dir, 0), e(b"notes", Kind::File, 2048), e(b"link", Kind::Symlink, 4)]);
    a
}

fn text(a: &App) -> Vec<String> {
    a.render().into_iter().map(|l| l.text).collect()
}

fn key(a: &mut App, k: Key) -> Vec<Cmd> {
    a.handle(Input::Key(k), Instant::now())
}

fn click(a: &mut App, row: u16, col: u16, t: Instant) -> Vec<Cmd> {
    a.handle(Input::Mouse(Mouse { kind: MouseKind::Press, button: 0, row, col }), t)
}

// ---------------------------------------------------------------- input decoding

#[test]
fn v1_keys_arrive_from_the_bytes_the_terminal_sends() {
    let mut p = InputParser::default();
    let k = |v: Vec<Input>| v.into_iter().map(|i| if let Input::Key(k) = i { k } else { panic!("{i:?}") }).collect::<Vec<_>>();
    assert_eq!(k(p.feed(b"\x1b[A\x1b[B\x1b[C\x1b[D")), vec![Key::Up, Key::Down, Key::Right, Key::Left]);
    assert_eq!(k(p.feed(b"\x1bOA\x1bOB\x1bOC\x1bOD\x1bOH\x1bOF")), vec![Key::Up, Key::Down, Key::Right, Key::Left, Key::Home, Key::End]);
    assert_eq!(k(p.feed(b"\x1b[5~\x1b[6~\x1b[H\x1b[F\x1b[1~\x1b[4~\x1b[7~\x1b[8~\x1b[3~")), vec![Key::PageUp, Key::PageDown, Key::Home, Key::End, Key::Home, Key::End, Key::Home, Key::End, Key::Delete]);
    assert_eq!(k(p.feed(b"\r\n\x7f\x08\tq")), vec![Key::Enter, Key::Enter, Key::Backspace, Key::Backspace, Key::Tab, Key::Char('q')]);
    assert_eq!(k(p.feed(b"\x03\x01\x1a")), vec![Key::Ctrl('c'), Key::Ctrl('a'), Key::Ctrl('z')]);
    assert_eq!(k(p.feed("é€😀".as_bytes())), vec![Key::Char('é'), Key::Char('€'), Key::Char('😀')]);
}

#[test]
fn v2_sequences_split_across_reads_and_a_lone_escape() {
    let mut p = InputParser::default();
    assert!(p.feed(b"\x1b").is_empty());
    assert!(p.feed(b"[").is_empty());
    assert_eq!(p.feed(b"A"), vec![Input::Key(Key::Up)]);
    assert!(p.feed(&"€".as_bytes()[..2]).is_empty(), "half of a character waits for the rest");
    assert_eq!(p.feed(&"€".as_bytes()[2..]), vec![Input::Key(Key::Char('€'))]);
    assert!(p.feed(b"\x1b").is_empty());
    assert_eq!(p.flush_pending(), Some(Input::Key(Key::Esc)), "an escape nothing followed is the Escape key");
    assert_eq!(p.flush_pending(), None);
    assert_eq!(p.feed(b"\x1b[<0;10;5"), vec![]);
    assert_eq!(p.feed(b"M"), vec![Input::Mouse(Mouse { kind: MouseKind::Press, button: 0, row: 4, col: 9 })]);
}

#[test]
fn v3_mouse_reports() {
    let mut p = InputParser::default();
    let m = |v: Vec<Input>| if let Input::Mouse(m) = v[0] { m } else { panic!() };
    assert_eq!(m(p.feed(b"\x1b[<0;1;1M")), Mouse { kind: MouseKind::Press, button: 0, row: 0, col: 0 });
    assert_eq!(m(p.feed(b"\x1b[<0;80;24m")), Mouse { kind: MouseKind::Release, button: 0, row: 23, col: 79 });
    assert_eq!(m(p.feed(b"\x1b[<2;5;5M")).button, 2);
    assert_eq!(m(p.feed(b"\x1b[<64;5;5M")).kind, MouseKind::Wheel(-1));
    assert_eq!(m(p.feed(b"\x1b[<65;5;5M")).kind, MouseKind::Wheel(1));
    assert_eq!(m(p.feed(b"\x1b[<32;5;6M")).kind, MouseKind::Drag);
    assert_eq!(m(p.feed(b"\x1b[<4;5;5M")).button, 0, "a modifier bit is not a button");
    assert_eq!(m(p.feed(b"\x1b[<0;99999999999;3M")).col, u16::MAX - 0, "an absurd column saturates instead of wrapping") ;
}

#[test]
fn v4_garbage_never_panics_and_never_sticks() {
    let mut p = InputParser::default();
    let mut x = 777u64;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for _ in 0..3000 {
        let n = (rnd() % 60) as usize;
        let b: Vec<u8> = (0..n).map(|_| match rnd() % 6 { 0 => 0x1b, 1 => b'[', 2 => b'<', 3 => b';', _ => rnd() as u8 }).collect();
        let _ = p.feed(&b);
    }
    p.feed(&[b'x'; 5]);
    assert_eq!(p.feed(b"\x1b[B"), vec![Input::Key(Key::Down)], "after any garbage the next real key still works");
    // a CSI that never ends is thrown away, not buffered forever
    let mut p = InputParser::default();
    p.feed(b"\x1b[");
    for _ in 0..200 {
        p.feed(b"1;");
    }
    assert_eq!(p.feed(b"\x1b[A"), vec![Input::Key(Key::Up)]);
    // the old three-byte mouse format is swallowed whole
    assert_eq!(p.feed(b"\x1b[M abc"), vec![Input::Key(Key::Char('c'))], "the three bytes after ESC [ M belong to it; the next byte is a key");
}

// ---------------------------------------------------------------- navigation

#[test]
fn v5_the_listing_is_ordered_and_moving_stays_inside() {
    let mut a = app(24, 80);
    let t = text(&a);
    let rows: Vec<&String> = t[2..9].iter().collect();
    assert!(rows[0].contains("../") && rows[1].contains("alpha/") && rows[2].contains("Beta/") && rows[3].contains("link@") && rows[4].contains("notes") && rows[5].contains("zeta.txt"), "{rows:?}");
    assert_eq!(a.selected_name(), None, "the first row is '..'");
    for _ in 0..20 {
        key(&mut a, Key::Down);
    }
    assert_eq!(a.selected_name(), Some(b"zeta.txt".to_vec()));
    for _ in 0..20 {
        key(&mut a, Key::Up);
    }
    assert_eq!(a.selected_name(), None);
    key(&mut a, Key::End);
    assert_eq!(a.selected_name(), Some(b"zeta.txt".to_vec()));
    key(&mut a, Key::Home);
    key(&mut a, Key::Char('j'));
    assert_eq!(a.selected_name(), Some(b"alpha".to_vec()));
}

#[test]
fn v6_a_long_list_scrolls_and_keeps_the_selection_in_view() {
    let mut a = App::new(b"/d".to_vec(), 10, 60, PathBuf::from("."));
    a.set_listing(b"/d".to_vec(), (0..100).map(|i| e(format!("f{i:03}").as_bytes(), Kind::File, i)).collect());
    for _ in 0..30 {
        key(&mut a, Key::PageDown);
    }
    assert!(text(&a).iter().any(|l| l.contains("f099")), "the end is reachable");
    let shown = text(&a);
    assert!(shown.iter().any(|l| l.starts_with(" f099")), "the selected last entry is on screen");
    key(&mut a, Key::Home);
    assert!(text(&a)[2].contains("../"), "back at the top");
    key(&mut a, Key::PageDown);
    let before = a.selected_name();
    a.handle(Input::Resize(4, 60), Instant::now());
    a.handle(Input::Resize(40, 60), Instant::now());
    assert_eq!(a.selected_name(), before, "resizing keeps the selection");
}

#[test]
fn v7_opening_going_up_and_returning_to_where_you_were() {
    let mut a = app(24, 80);
    key(&mut a, Key::Down);
    assert_eq!(key(&mut a, Key::Enter), vec![Cmd::List(b"/home/u/alpha".to_vec())]);
    a.set_listing(b"/home/u/alpha".to_vec(), vec![e(b"inner", Kind::File, 1)]);
    assert_eq!(key(&mut a, Key::Backspace), vec![Cmd::List(b"/home/u".to_vec())]);
    a.set_listing(b"/home/u".to_vec(), vec![e(b"alpha", Kind::Dir, 0), e(b"zzz", Kind::File, 1)]);
    assert_eq!(a.selected_name(), Some(b"alpha".to_vec()), "going up selects the directory you came from");
    key(&mut a, Key::Home);
    assert_eq!(key(&mut a, Key::Enter), vec![Cmd::List(b"/home".to_vec())], "Enter on '..'");
    // at the root there is no '..'
    let mut r = App::new(b"/".to_vec(), 24, 80, PathBuf::from("."));
    r.set_listing(b"/".to_vec(), vec![e(b"etc", Kind::Dir, 0)]);
    assert_eq!(r.selected_name(), Some(b"etc".to_vec()));
    assert!(key(&mut r, Key::Backspace).is_empty());
    assert_eq!(key(&mut r, Key::Enter), vec![Cmd::List(b"/etc".to_vec())], "no double slash under the root");
    assert_eq!(parent(b"/a/b/"), b"/a".to_vec());
    assert_eq!(parent(b"/a"), b"/".to_vec());
    assert_eq!(parent(b"/"), b"/".to_vec());
    assert_eq!(join(b"/", b"x"), b"/x".to_vec());
    assert_eq!(join(b"/a b/", b"c d"), b"/a b/c d".to_vec());
}

// ---------------------------------------------------------------- mouse

#[test]
fn v8_a_click_selects_a_double_click_opens_and_the_wheel_scrolls() {
    let mut a = app(24, 80);
    let t0 = Instant::now();
    assert!(click(&mut a, 3, 10, t0).is_empty());
    assert_eq!(a.selected_name(), Some(b"alpha".to_vec()), "row 3 is the second entry ('..' is row 2)");
    assert_eq!(click(&mut a, 3, 10, t0 + Duration::from_millis(200)), vec![Cmd::List(b"/home/u/alpha".to_vec())], "a double click opens");
    assert!(click(&mut a, 3, 10, t0 + Duration::from_millis(250)).is_empty(), "the third click starts over");
    // two slow clicks are two single clicks
    let mut a = app(24, 80);
    click(&mut a, 3, 10, t0);
    assert!(click(&mut a, 3, 10, t0 + Duration::from_secs(2)).is_empty());
    // two clicks on different rows are not a double click
    let mut a = app(24, 80);
    assert!(click(&mut a, 3, 10, t0).is_empty());
    assert!(click(&mut a, 4, 10, t0 + Duration::from_millis(100)).is_empty());
    assert_eq!(a.selected_name(), Some(b"Beta".to_vec()));
    // clicking where nothing is
    let sel = a.selected_name();
    for (r, c) in [(0, 5), (1, 5), (20, 5), (9, 5), (23, 79), (500, 500)] {
        assert!(click(&mut a, r, c, t0).is_empty(), "row {r}");
    }
    assert_eq!(a.selected_name(), sel);
    // other buttons and drags do nothing
    a.handle(Input::Mouse(Mouse { kind: MouseKind::Press, button: 2, row: 3, col: 5 }), t0);
    a.handle(Input::Mouse(Mouse { kind: MouseKind::Drag, button: 0, row: 5, col: 5 }), t0);
    assert_eq!(a.selected_name(), sel);
    a.handle(Input::Mouse(Mouse { kind: MouseKind::Wheel(1), button: 0, row: 5, col: 5 }), t0);
    assert_ne!(a.selected_name(), sel, "the wheel moves the selection");
}

#[test]
fn v9_the_buttons_at_the_bottom_can_be_clicked() {
    let mut a = app(24, 80);
    let bar = text(&a).last().unwrap().clone();
    let col_of = |label: &str| bar.find(label).unwrap_or_else(|| panic!("{label} not in {bar:?}")) as u16;
    let t = Instant::now();
    click(&mut a, 3, 5, t);
    click(&mut a, 3, 5, t + Duration::from_secs(5)); // alpha selected (a directory): download refuses
    assert!(click(&mut a, 23, col_of("d:down"), t).is_empty());
    assert!(text(&a)[22].contains("only files"), "{:?}", text(&a)[22]);
    for _ in 0..4 {
        key(&mut a, Key::Down);
    }
    key(&mut a, Key::Up);
    key(&mut a, Key::Down);
    assert_eq!(a.selected_name(), Some(b"zeta.txt".to_vec()));
    let c = click(&mut a, 23, col_of("d:down") + 3, t);
    assert!(matches!(c.as_slice(), [Cmd::Download { remote, local }] if remote == b"/home/u/zeta.txt" && local == &PathBuf::from("/tmp/dl/zeta.txt")), "{c:?}");
    assert!(click(&mut a, 23, col_of("m:mkdir"), t).is_empty());
    assert!(text(&a)[22].contains("new directory name"), "the mkdir button opens the prompt");
    key(&mut a, Key::Esc);
    assert_eq!(click(&mut a, 23, col_of("q:quit"), t), vec![Cmd::Quit]);
    assert!(click(&mut a, 23, 79, t).is_empty(), "between buttons nothing happens");
    // a narrow screen shows fewer buttons, never a broken one
    let n = app(24, 30);
    let bar = text(&n).last().unwrap().clone();
    assert_eq!(bar.chars().count(), 30);
    assert!(bar.contains("d:down") && !bar.contains("q:quit"));
}

// ---------------------------------------------------------------- prompts and confirmation

fn type_text(a: &mut App, s: &str) {
    for c in s.chars() {
        key(a, Key::Char(c));
    }
}

#[test]
fn v10_creating_renaming_uploading_going_somewhere() {
    let mut a = app(24, 80);
    key(&mut a, Key::Char('m'));
    type_text(&mut a, "new dir");
    assert_eq!(key(&mut a, Key::Enter), vec![Cmd::Mkdir(b"/home/u/new dir".to_vec())]);
    // bad names stay in the prompt with an explanation
    for bad in ["", ".", "..", "a/b", "/abs"] {
        key(&mut a, Key::Char('m'));
        type_text(&mut a, bad);
        assert!(key(&mut a, Key::Enter).is_empty(), "{bad:?}");
        assert!(text(&a)[22].contains('!') || text(&a)[22].contains("new directory name"), "{:?}", text(&a)[22]);
        key(&mut a, Key::Esc);
    }
    // rename starts from the old name and can be edited
    key(&mut a, Key::Home);
    key(&mut a, Key::Char('j'));
    key(&mut a, Key::Char('j')); // Beta
    key(&mut a, Key::Char('r'));
    assert!(text(&a)[22].contains("new name: Beta"));
    key(&mut a, Key::Left);
    key(&mut a, Key::Backspace);
    type_text(&mut a, "X");
    key(&mut a, Key::Home);
    type_text(&mut a, ">");
    key(&mut a, Key::End);
    key(&mut a, Key::Char('!'));
    key(&mut a, Key::Delete);
    assert_eq!(key(&mut a, Key::Enter), vec![Cmd::Rename { from: b"/home/u/Beta".to_vec(), to: b"/home/u/>BeXa!".to_vec() }]);
    // an unchanged name is not a command
    key(&mut a, Key::Char('r'));
    assert!(key(&mut a, Key::Enter).is_empty());
    // upload takes a local path and names the remote file after it
    key(&mut a, Key::Char('u'));
    type_text(&mut a, "/some/dir/photo 1.jpg");
    assert_eq!(key(&mut a, Key::Enter), vec![Cmd::Upload { local: PathBuf::from("/some/dir/photo 1.jpg"), remote: b"/home/u/photo 1.jpg".to_vec() }]);
    key(&mut a, Key::Char('u'));
    type_text(&mut a, "/");
    assert!(key(&mut a, Key::Enter).is_empty(), "a directory is not a file name");
    key(&mut a, Key::Esc);
    // goto: absolute or relative to here
    key(&mut a, Key::Char('g'));
    type_text(&mut a, "/var/log");
    assert_eq!(key(&mut a, Key::Enter), vec![Cmd::List(b"/var/log".to_vec())]);
    key(&mut a, Key::Char('g'));
    type_text(&mut a, "../x");
    assert_eq!(key(&mut a, Key::Enter), vec![Cmd::List(b"/home/u/../x".to_vec())]);
    key(&mut a, Key::Char('g'));
    assert!(key(&mut a, Key::Enter).is_empty());
}

#[test]
fn v11_the_editor_of_a_prompt_is_safe() {
    let mut a = app(24, 80);
    key(&mut a, Key::Char('m'));
    for c in ['\x1b', '\0', '\x07', '\u{85}'] {
        key(&mut a, Key::Char(c));
    }
    type_text(&mut a, "ok");
    assert_eq!(key(&mut a, Key::Enter), vec![Cmd::Mkdir(b"/home/u/ok".to_vec())], "control characters never enter the text");
    key(&mut a, Key::Char('g'));
    for _ in 0..6000 {
        key(&mut a, Key::Char('x'));
    }
    key(&mut a, Key::Ctrl('u'));
    type_text(&mut a, "/short");
    assert_eq!(key(&mut a, Key::Enter), vec![Cmd::List(b"/short".to_vec())], "the length is capped and a line can be cleared");
    // arrows beyond the ends are harmless
    key(&mut a, Key::Char('m'));
    for _ in 0..5 {
        key(&mut a, Key::Left);
        key(&mut a, Key::Backspace);
        key(&mut a, Key::Delete);
    }
    type_text(&mut a, "é€😀");
    key(&mut a, Key::Left);
    key(&mut a, Key::Backspace);
    assert_eq!(key(&mut a, Key::Enter), vec![Cmd::Mkdir("/home/u/é😀".as_bytes().to_vec())], "editing works on characters, not bytes");
}

#[test]
fn v12_delete_asks_first_and_only_y_means_yes() {
    let mut a = app(24, 80);
    key(&mut a, Key::Home);
    key(&mut a, Key::Char('x'));
    assert!(!text(&a)[22].contains("delete"), "nothing to delete on '..'");
    key(&mut a, Key::Char('j'));
    key(&mut a, Key::Char('x'));
    assert!(text(&a)[22].contains("delete alpha ? (y/N)"));
    assert!(key(&mut a, Key::Enter).is_empty(), "Enter is 'no'");
    assert!(text(&a)[22].contains("not deleted"));
    key(&mut a, Key::Delete);
    assert!(key(&mut a, Key::Char('n')).is_empty());
    key(&mut a, Key::Char('x'));
    assert_eq!(key(&mut a, Key::Char('y')), vec![Cmd::Remove(b"/home/u/alpha".to_vec())]);
    key(&mut a, Key::Char('x'));
    assert!(key(&mut a, Key::Esc).is_empty(), "Escape cancels and does not quit");
    key(&mut a, Key::Char('x'));
    key(&mut a, Key::Char('Y'));
    key(&mut a, Key::Char('?'));
    assert!(text(&a)[0].contains("keys"));
    assert!(key(&mut a, Key::Char('q')).is_empty(), "inside the help every key just closes it");
    assert_eq!(key(&mut a, Key::Char('q')), vec![Cmd::Quit]);
}

#[test]
fn v13_refresh_and_quit_keys() {
    let mut a = app(24, 80);
    key(&mut a, Key::Char('j'));
    key(&mut a, Key::Char('j'));
    assert_eq!(key(&mut a, Key::Char('R')), vec![Cmd::List(b"/home/u".to_vec())]);
    a.set_listing(b"/home/u".to_vec(), vec![e(b"Beta", Kind::Dir, 0), e(b"alpha", Kind::Dir, 0)]);
    assert_eq!(a.selected_name(), Some(b"Beta".to_vec()), "a refresh keeps the selected name");
    assert_eq!(key(&mut a, Key::Char('~')), vec![Cmd::List(b".".to_vec())]);
    assert_eq!(key(&mut a, Key::Ctrl('c')), vec![Cmd::Quit]);
    assert_eq!(key(&mut a, Key::Esc), vec![Cmd::Quit]);
    let mut empty = App::new(b"/e".to_vec(), 24, 80, PathBuf::from("."));
    empty.set_listing(b"/e".to_vec(), vec![]);
    for k in [Key::Down, Key::Up, Key::Enter, Key::Char('d'), Key::Char('x'), Key::Char('r'), Key::PageDown, Key::End] {
        let _ = key(&mut empty, k);
    }
    assert!(text(&empty)[22].contains("0 entries") || !text(&empty)[22].is_empty());
}

// ---------------------------------------------------------------- the other machine cannot act on this terminal

fn assert_clean(lines: &[String], what: &str) {
    for (i, l) in lines.iter().enumerate() {
        for c in l.chars() {
            assert!(!c.is_control(), "{what}: line {i} holds the control character {:?}: {l:?}", c);
            assert!(!matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200B}'..='\u{200F}' | '\u{FEFF}'), "{what}: line {i} holds an invisible/reordering character {:?}", c);
        }
    }
}

#[test]
fn v14_hostile_names_and_messages_are_shown_as_harmless_text() {
    let hostile: Vec<&[u8]> = vec![
        b"\x1b]0;pwned\x07title",
        b"\x1b[2J\x1b[H",
        b"\x1b[31mred\x1b[0m",
        b"line\nbreak\rcarriage",
        b"\x9b31m c1 csi",
        b"\x07bell\x08\x08back",
        "evil\u{202E}gpj.exe".as_bytes(),
        "iso\u{2066}late".as_bytes(),
        "zero\u{200B}width".as_bytes(),
        b"invalid\xff\xfeutf8",
        b"\x1bP1$r\x1b\\dcs",
        b"\x1b_Gi=1;AAAA\x1b\\apc",
        "A very long name ".repeat(40).as_bytes().to_vec().leak(),
    ];
    let mut a = App::new(b"/ev\x1b[2Jil".to_vec(), 24, 80, PathBuf::from("."));
    a.set_listing(b"/ev\x1b[2Jil\xd8".to_vec(), hostile.iter().map(|n| e(n, Kind::File, 1)).collect());
    assert_clean(&text(&a), "listing");
    a.error("server said: \x1b[31m\x1b]52;c;ZXZpbA==\x07 bad");
    assert_clean(&text(&a), "error text");
    a.note("\x1b[?1049h");
    assert_clean(&text(&a), "note");
    for i in 0..hostile.len() + 1 {
        key(&mut a, Key::Down);
        let _ = i;
        assert_clean(&text(&a), "selected rows");
    }
    key(&mut a, Key::Char('x'));
    assert_clean(&text(&a), "delete confirmation");
    key(&mut a, Key::Char('n'));
    key(&mut a, Key::Char('r'));
    assert_clean(&text(&a), "rename prompt prefilled with a hostile name");
    key(&mut a, Key::Esc);
    key(&mut a, Key::Char('?'));
    assert_clean(&text(&a), "help");
    assert_eq!(sanitize(b"a\x1b[2Jb"), "a?[2Jb");
    assert_eq!(sanitize("plain é€😀".as_bytes()), "plain é€😀");
}

#[test]
fn v15_hostile_names_cannot_aim_a_download_or_a_rename_outside_the_folder() {
    let mut a = App::new(b"/d".to_vec(), 24, 80, PathBuf::from("/safe/downloads"));
    a.set_listing(b"/d".to_vec(), vec![e(b"../../etc/passwd", Kind::File, 1), e(b"/etc/shadow", Kind::File, 1), e(b"..", Kind::Dir, 0), e(b".", Kind::Dir, 0), e(b"", Kind::File, 0), e(b"nul\0byte", Kind::File, 0), e(b"fine.txt", Kind::File, 1), e(b"a/b", Kind::File, 1)]);
    let t = text(&a).join("\n");
    assert!(t.contains("fine.txt") && !t.contains("passwd") && !t.contains("shadow") && !t.contains("a/b"), "entries that are not one plain name are dropped:\n{t}");
    key(&mut a, Key::Down);
    let c = key(&mut a, Key::Char('d'));
    assert_eq!(c, vec![Cmd::Download { remote: b"/d/fine.txt".to_vec(), local: PathBuf::from("/safe/downloads/fine.txt") }]);
}

#[test]
fn v16_drawing_fits_every_screen_size() {
    for (rows, cols) in [(1, 1), (1, 80), (2, 5), (3, 10), (4, 20), (5, 33), (6, 51), (7, 52), (24, 80), (24, 200), (60, 300), (200, 17)] {
        let mut a = App::new(b"/very/long/path/".repeat(10), rows, cols, PathBuf::from("."));
        a.set_listing(b"/very/long/path/".repeat(10), vec![e("ünïcödé-naam-😀😀😀".as_bytes(), Kind::File, u64::MAX), e(&b"x".repeat(900), Kind::Dir, 0), e(b"short", Kind::Symlink, 12), e("日本語のファイル名".as_bytes(), Kind::File, 5)]);
        for step in 0..8 {
            let lines = a.render();
            assert_eq!(lines.len(), rows as usize, "{rows}x{cols}: the picture has exactly as many lines as the screen");
            for (i, l) in lines.iter().enumerate() {
                assert_eq!(l.text.chars().count(), cols as usize, "{rows}x{cols} line {i}: {:?}", l.text);
            }
            let _ = key(&mut a, [Key::Down, Key::PageDown, Key::Char('m'), Key::Char('a'), Key::Esc, Key::Char('?'), Key::Esc, Key::End][step]);
        }
    }
}

#[test]
fn v17_formatting_helpers() {
    assert_eq!(human_size(0), "0B");
    assert_eq!(human_size(1023), "1023B");
    assert_eq!(human_size(1024), "1.0K");
    assert_eq!(human_size(1536), "1.5K");
    assert_eq!(human_size(5 << 20), "5.0M");
    assert_eq!(human_size(u64::MAX), "16777216.0T");
    assert_eq!(fmt_time(0), "1970-01-01 00:00");
    assert_eq!(fmt_time(951782400), "2000-02-29 00:00");
    assert_eq!(fmt_time(1_760_000_000), "2025-10-09 08:53");
    assert_eq!(fmt_time(-86400), "1969-12-31 00:00");
    assert_eq!(fmt_time(i64::MAX / 1000), fmt_time(i64::MAX / 1000));
    assert_eq!(fmt_mode(Kind::File, 0o644), "-rw-r--r--");
    assert_eq!(fmt_mode(Kind::Dir, 0o755), "drwxr-xr-x");
    assert_eq!(fmt_mode(Kind::Symlink, 0o777), "lrwxrwxrwx");
    assert_eq!(fmt_mode(Kind::Other, 0o000), "?---------");
    assert!(valid_new_name("ok name") && valid_new_name("é") && valid_new_name("..x") && valid_new_name(".hidden"));
    assert!(!valid_new_name("") && !valid_new_name(".") && !valid_new_name("..") && !valid_new_name("a/b") && !valid_new_name("a\nb") && !valid_new_name(&"x".repeat(256)));
}

#[test]
fn v18_a_listing_arriving_meanwhile_does_not_cancel_a_prompt_or_a_confirmation() {
    let mut a = app(24, 80);
    key(&mut a, Key::Char('j'));
    key(&mut a, Key::Char('x'));
    a.set_listing(b"/home/u".to_vec(), vec![e(b"other", Kind::File, 1), e(b"alpha", Kind::Dir, 0)]);
    assert!(text(&a)[22].contains("delete alpha ? (y/N)"), "{:?}", text(&a)[22]);
    assert_eq!(key(&mut a, Key::Char('y')), vec![Cmd::Remove(b"/home/u/alpha".to_vec())], "the confirmation still means the same thing");
    key(&mut a, Key::Char('m'));
    type_text(&mut a, "abc");
    a.set_listing(b"/home/u".to_vec(), vec![]);
    type_text(&mut a, "d");
    assert_eq!(key(&mut a, Key::Enter), vec![Cmd::Mkdir(b"/home/u/abcd".to_vec())], "what was typed is kept");
}

#[test]
fn v19_after_a_rename_the_selection_follows_the_new_name() {
    let mut a = app(24, 80);
    key(&mut a, Key::Char('j'));
    key(&mut a, Key::Char('j')); // Beta
    key(&mut a, Key::Char('r'));
    key(&mut a, Key::Ctrl('u'));
    type_text(&mut a, "Gamma");
    key(&mut a, Key::Enter);
    assert_eq!(key(&mut a, Key::Char('R')), vec![Cmd::List(b"/home/u".to_vec())]);
    a.set_listing(b"/home/u".to_vec(), vec![e(b"alpha", Kind::Dir, 0), e(b"Gamma", Kind::Dir, 0), e(b"zeta.txt", Kind::File, 1)]);
    assert_eq!(a.selected_name(), Some(b"Gamma".to_vec()));
}

#[test]
fn v20_edges_of_the_screen_and_of_the_input() {
    // a click on the status line is not a click on the list, even when the list fills the screen
    let mut a = App::new(b"/d".to_vec(), 8, 80, PathBuf::from("."));
    a.set_listing(b"/d".to_vec(), (0..10).map(|i| e(format!("f{i}").as_bytes(), Kind::File, 1)).collect());
    let t = Instant::now();
    click(&mut a, 5, 5, t); // the last list row (rows 2..=5)
    let last_shown = a.selected_name();
    assert_eq!(last_shown, Some(b"f2".to_vec()), "rows 2..=5 show ../, f0, f1, f2");
    click(&mut a, 6, 5, t + Duration::from_secs(9)); // the status line
    assert_eq!(a.selected_name(), last_shown, "row 6 is the status line");
    // on a screen too small for the button bar the last row is not a button
    let mut tiny = app(3, 80);
    key(&mut tiny, Key::Down); // a directory is selected: the 'd' button would answer with an error
    click(&mut tiny, 2, 2, t);
    assert!(text(&tiny)[2].contains("entries"), "{:?}", text(&tiny)[2]);
    // the typed text of a prompt is capped
    let mut p = app(24, 80);
    key(&mut p, Key::Char('g'));
    for _ in 0..4200 {
        key(&mut p, Key::Char('a'));
    }
    let cmd = key(&mut p, Key::Enter);
    match cmd.as_slice() {
        [Cmd::List(path)] => assert_eq!(path.len(), b"/home/u/".len() + 4096),
        other => panic!("{other:?}"),
    }
    // Enter on '..' goes up and remembers where it came from
    let mut u = app(24, 80);
    key(&mut u, Key::Enter);
    u.set_listing(b"/home".to_vec(), vec![e(b"aaa", Kind::Dir, 0), e(b"u", Kind::Dir, 0), e(b"zzz", Kind::Dir, 0)]);
    assert_eq!(u.selected_name(), Some(b"u".to_vec()));
    // a report that only looks like a mouse report is nothing
    let mut ip = InputParser::default();
    assert!(ip.feed(b"\x1b[<0;1;1H").is_empty());
    assert!(ip.feed(b"\x1b[<0;1;1").is_empty());
    assert!(ip.feed(b"A").is_empty(), "ESC [ <0;1;1 A is one meaningless sequence, not a key plus a letter");
}
