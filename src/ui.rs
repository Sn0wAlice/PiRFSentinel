//! Terminal UI, in the spirit of mlab-sh/postmortem: a live braille spinner with
//! scan stats on stderr, colored match blocks printed above it. Animation and
//! color switch off when the terminal isn't a TTY, with NO_COLOR, or in --json
//! mode, so journald / pipes get plain lines.

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

static COLOR: AtomicBool = AtomicBool::new(false);
static BAR: OnceLock<ProgressBar> = OnceLock::new();

const TICK: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Sets up color and the live spinner. Returns whether the UI is animated.
pub fn init(animate: bool) -> bool {
    let tty = std::io::stdout().is_terminal() && std::io::stderr().is_terminal();
    let on = animate && tty && std::env::var_os("NO_COLOR").is_none();
    COLOR.store(on, Ordering::Relaxed);
    let pb = ProgressBar::new_spinner();
    if on {
        pb.set_style(ProgressStyle::with_template("{spinner:.magenta} {msg}").unwrap().tick_strings(TICK));
        pb.enable_steady_tick(Duration::from_millis(80));
    } else {
        pb.set_draw_target(ProgressDrawTarget::hidden());
    }
    let _ = BAR.set(pb);
    on
}

pub fn animated() -> bool {
    COLOR.load(Ordering::Relaxed)
}

/// Updates the live status line (no-op when not animated).
pub fn status(msg: String) {
    if let Some(pb) = BAR.get() {
        pb.set_message(msg);
    }
}

/// Prints to stdout without tearing the spinner.
pub fn out(s: &str) {
    match BAR.get() {
        Some(pb) if animated() => pb.suspend(|| println!("{s}")),
        _ => println!("{s}"),
    }
}

/// Prints a diagnostic to stderr without tearing the spinner.
pub fn note(s: &str) {
    match BAR.get() {
        Some(pb) if animated() => pb.suspend(|| eprintln!("{s}")),
        _ => eprintln!("{s}"),
    }
}

pub fn finish() {
    if let Some(pb) = BAR.get() {
        pb.finish_and_clear();
    }
}

fn sgr(code: &str, s: &str) -> String {
    if animated() { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
}

pub fn bold(s: &str) -> String { sgr("1", s) }
pub fn dim(s: &str) -> String { sgr("2", s) }
pub fn red(s: &str) -> String { sgr("1;31", s) }
pub fn orange(s: &str) -> String { sgr("38;2;255;165;0", s) }
pub fn purple(s: &str) -> String { sgr("38;2;167;139;250", s) }
pub fn green(s: &str) -> String { sgr("32", s) }
