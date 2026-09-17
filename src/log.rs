//! What the core says about what it is doing.
//!
//! One line each on standard output: the reader is the application that started this process, and
//! that is the channel it already has. No timestamps — the reader stamps lines as they arrive, and
//! two clocks on one line only disagree.
//!
//! The level word comes first, spelled the way the application's classifier expects, so a line from
//! this core is coloured by the same rule as one from the engine beside it.
//!
//! The level is one atomic integer read before a message is built, so a line that will not be
//! printed costs a load and a comparison. That is what makes a `debug!` affordable on the packet
//! path.

use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};

/// How much is said. Ordered from least to most: a level enables itself and everything above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// Something failed and will not be retried into working.
    Error = 0,
    /// Something is wrong but the core is carrying on.
    Warn = 1,
    /// A decision a person would want to know about without asking: the policy changed, the tunnel
    /// moved, the routed set is different.
    Notice = 2,
    /// One line per thing that happened — a query answered, a set applied.
    Info = 3,
    /// The contents: which addresses, which prefixes, which packet.
    Debug = 4,
}

impl Level {
    /// The word that starts the line, and the word the application classifies by.
    pub fn word(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Notice => "NOTICE",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
        }
    }

    /// Read a level as a person writes it. Anything unrecognised is refused rather than guessed:
    /// silently falling back would mean a request to see more producing exactly what it did before.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Level::Error),
            "warn" | "warning" => Some(Level::Warn),
            "notice" => Some(Level::Notice),
            "info" => Some(Level::Info),
            "debug" | "trace" => Some(Level::Debug),
            _ => None,
        }
    }

    fn from_stored(value: u8) -> Self {
        match value {
            0 => Level::Error,
            1 => Level::Warn,
            2 => Level::Notice,
            4 => Level::Debug,
            _ => Level::Info,
        }
    }
}

/// One line per thing that happened is the default: enough to answer "why did that name go there"
/// without being asked in advance, and not so much that a busy machine drowns its own journal.
static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Change how much is said. Takes effect on the next line, from any thread, with nothing to
/// restart: that is why the level is an integer and not a field on something.
pub fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

/// How much is being said right now.
pub fn level() -> Level {
    Level::from_stored(LEVEL.load(Ordering::Relaxed))
}

/// Whether a line at this level would be printed. Checked before the message is built.
pub fn enabled(level: Level) -> bool {
    level as u8 <= LEVEL.load(Ordering::Relaxed)
}

/// Write one line. Called through the macros, which check the level first.
pub fn emit(level: Level, scope: &str, message: &str) {
    // One write, taking the lock once: two writes could interleave with another thread's line and
    // produce a line that belongs to neither.
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{:<6} {:<8} {message}", level.word(), scope);
}

/// The macros. Each checks the level before building anything, so an argument that costs something
/// to format costs nothing when it would not be printed.
#[macro_export]
macro_rules! log_at {
    ($level:expr, $scope:expr, $($arg:tt)*) => {
        if $crate::log::enabled($level) {
            $crate::log::emit($level, $scope, &format!($($arg)*));
        }
    };
}

/// Something failed and will not be retried into working.
#[macro_export]
macro_rules! error {
    ($scope:expr, $($arg:tt)*) => { $crate::log_at!($crate::log::Level::Error, $scope, $($arg)*) };
}

/// Something is wrong and the core is carrying on.
#[macro_export]
macro_rules! warn {
    ($scope:expr, $($arg:tt)*) => { $crate::log_at!($crate::log::Level::Warn, $scope, $($arg)*) };
}

/// A decision a person would want to know about without having asked.
#[macro_export]
macro_rules! notice {
    ($scope:expr, $($arg:tt)*) => { $crate::log_at!($crate::log::Level::Notice, $scope, $($arg)*) };
}

/// One line per thing that happened.
#[macro_export]
macro_rules! info {
    ($scope:expr, $($arg:tt)*) => { $crate::log_at!($crate::log::Level::Info, $scope, $($arg)*) };
}

/// The contents: which addresses, which prefixes, which packet.
#[macro_export]
macro_rules! debug {
    ($scope:expr, $($arg:tt)*) => { $crate::log_at!($crate::log::Level::Debug, $scope, $($arg)*) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The levels have to compare in the order they are declared, because that ordering is what
    /// `enabled` means. Reordering the enum without noticing would silently change what is printed.
    #[test]
    fn a_level_enables_itself_and_everything_more_severe() {
        set_level(Level::Notice);
        assert!(enabled(Level::Error));
        assert!(enabled(Level::Warn));
        assert!(enabled(Level::Notice));
        assert!(!enabled(Level::Info));
        assert!(!enabled(Level::Debug));

        set_level(Level::Debug);
        assert!(enabled(Level::Debug));
        assert!(enabled(Level::Error));

        set_level(Level::Error);
        assert!(enabled(Level::Error));
        assert!(!enabled(Level::Warn));

        // Left as the rest of the suite expects to find it.
        set_level(Level::Info);
    }

    #[test]
    fn a_level_is_read_the_way_a_person_writes_it() {
        assert_eq!(Level::parse("debug"), Some(Level::Debug));
        assert_eq!(Level::parse(" WARN "), Some(Level::Warn));
        assert_eq!(Level::parse("warning"), Some(Level::Warn));
        assert_eq!(Level::parse("Notice"), Some(Level::Notice));
    }

    /// A level nobody recognises is refused. Guessing would mean a request to see more producing
    /// exactly what it produced before, with nothing said about why.
    #[test]
    fn a_level_nobody_recognises_is_refused_rather_than_guessed() {
        assert_eq!(Level::parse("loud"), None);
        assert_eq!(Level::parse(""), None);
    }

    /// The words are what the application classifies by, so they are part of the interface rather
    /// than an implementation detail of this module.
    #[test]
    fn the_words_are_the_ones_the_reader_looks_for() {
        assert_eq!(Level::Error.word(), "ERROR");
        assert_eq!(Level::Warn.word(), "WARN");
        assert_eq!(Level::Notice.word(), "NOTICE");
        assert_eq!(Level::Info.word(), "INFO");
        assert_eq!(Level::Debug.word(), "DEBUG");
    }
}
