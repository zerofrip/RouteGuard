//! In-memory log ring for logs.tail and diagnostics export.

use std::collections::VecDeque;
use std::sync::Mutex;

const MAX_LINES: usize = 200;
const MAX_BYTES: usize = 4096;

pub struct LogRing {
    lines: Mutex<VecDeque<String>>,
    bytes: Mutex<usize>,
}

impl LogRing {
    pub fn new() -> Self {
        Self {
            lines: Mutex::new(VecDeque::new()),
            bytes: Mutex::new(0),
        }
    }

    pub fn push(&self, line: impl Into<String>) {
        let line = line.into();
        let len = line.len() + 1;
        let mut lines = self.lines.lock().unwrap();
        let mut bytes = self.bytes.lock().unwrap();
        lines.push_back(line);
        *bytes += len;
        while lines.len() > MAX_LINES || *bytes > MAX_BYTES {
            if let Some(old) = lines.pop_front() {
                *bytes = bytes.saturating_sub(old.len() + 1);
            } else {
                break;
            }
        }
    }

    pub fn tail(&self, limit: usize) -> Vec<String> {
        let lines = self.lines.lock().unwrap();
        lines.iter().rev().take(limit).cloned().rev().collect()
    }
}

impl Default for LogRing {
    fn default() -> Self {
        Self::new()
    }
}

pub fn init_log_hook(ring: std::sync::Arc<LogRing>) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("routeguard=info".parse().unwrap()),
        )
        .with_writer(move || LogWriter(ring.clone()))
        .init();
}

struct LogWriter(std::sync::Arc<LogRing>);

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(s) = std::str::from_utf8(buf) {
            for line in s.lines() {
                if !line.is_empty() {
                    self.0.push(line.to_string());
                }
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
