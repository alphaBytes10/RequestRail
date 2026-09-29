//! Pipeline deadline support.

use std::time::{Duration, Instant};

/// A deadline for the entire pipeline evaluation.
///
/// When a deadline is set, the pipeline checks before running each guard
/// whether the deadline has elapsed. If it has, the pipeline short-circuits
/// with a `DeadlineExceeded` error.
#[derive(Debug, Clone)]
pub struct Deadline {
    start: Instant,
    timeout: Duration,
}

impl Deadline {
    /// Create a new deadline that expires after `timeout`.
    pub fn new(timeout: Duration) -> Self {
        Self {
            start: Instant::now(),
            timeout,
        }
    }

    /// Returns `true` if the deadline has been exceeded.
    pub fn is_exceeded(&self) -> bool {
        self.start.elapsed() >= self.timeout
    }

    /// Returns the remaining time, or `Duration::ZERO` if expired.
    pub fn remaining(&self) -> Duration {
        self.timeout.saturating_sub(self.start.elapsed())
    }

    /// Returns the configured timeout duration.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn deadline_not_exceeded() {
        let dl = Deadline::new(Duration::from_secs(10));
        assert!(!dl.is_exceeded());
        assert!(dl.remaining() > Duration::ZERO);
    }

    #[test]
    fn deadline_exceeded() {
        let dl = Deadline::new(Duration::from_millis(10));
        thread::sleep(Duration::from_millis(20));
        assert!(dl.is_exceeded());
        assert_eq!(dl.remaining(), Duration::ZERO);
    }
}
