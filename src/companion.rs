//! Small shared, read-only startup sequence for serial, TCP, and BLE.
use std::time::{Duration, Instant};

pub fn app_start() -> Vec<u8> {
    let mut bytes = vec![1, 0, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(b"meshages");
    bytes
}
#[derive(Clone, Copy)]
enum Stage {
    App,
    Info,
    Scope,
    Channel(u8),
    Done,
}
pub struct Startup {
    stage: Stage,
    channels: u8,
    deadline: Instant,
    pub notice: Option<String>,
}
impl Startup {
    pub fn new(now: Instant) -> Self {
        Self {
            stage: Stage::App,
            channels: 0,
            deadline: now + Duration::from_secs(3),
            notice: None,
        }
    }
    pub fn step(&mut self, frame: Option<&[u8]>, now: Instant) -> Option<Vec<u8>> {
        let frame = frame.unwrap_or(&[]);
        let error = matches!(frame.first(), Some(1 | 0x0f));
        let timeout = now >= self.deadline;
        let command = match self.stage {
            Stage::App if frame.first() == Some(&5) || timeout => {
                self.stage = Stage::Info;
                Some(vec![22, 3])
            }
            Stage::Info
                if (frame.first() == Some(&0x0d) && frame.len() >= 4) || error || timeout =>
            {
                if frame.first() == Some(&0x0d) && frame.len() >= 4 {
                    self.channels = frame[3];
                }
                self.stage = Stage::Scope;
                Some(vec![64])
            }
            Stage::Scope
                if (frame.first() == Some(&0x1c) && matches!(frame.len(), 1 | 48))
                    || error
                    || timeout =>
            {
                if error || timeout {
                    self.notice = Some("Default region unavailable from this companion".into());
                }
                self.next_channel(0)
            }
            Stage::Channel(i)
                if (frame.first() == Some(&0x12) && frame.len() == 50 && frame[1] == i)
                    || error =>
            {
                self.next_channel(i as u16 + 1)
            }
            Stage::Channel(_) if timeout => {
                self.stage = Stage::Done;
                self.notice = Some("Channel import timed out · capture continues".into());
                None
            }
            _ => None,
        };
        if command.is_some() {
            self.deadline = now + Duration::from_secs(3);
        }
        command
    }
    fn next_channel(&mut self, i: u16) -> Option<Vec<u8>> {
        if i < self.channels as u16 {
            self.stage = Stage::Channel(i as u8);
            Some(vec![31, i as u8])
        } else {
            self.stage = Stage::Done;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queries_default_and_every_channel_without_writes_or_rf_commands() {
        let now = Instant::now();
        let mut s = Startup::new(now);
        assert_eq!(s.step(Some(&[5]), now), Some(vec![22, 3]));
        assert_eq!(s.step(Some(&[0x88, 0, 0]), now), None);
        assert_eq!(s.step(Some(&[13, 14, 100, 3]), now), Some(vec![64]));
        assert_eq!(s.step(Some(&[1, 1]), now), Some(vec![31, 0]));
        let mut channel = vec![0; 50];
        channel[0] = 18;
        assert_eq!(s.step(Some(&channel), now), Some(vec![31, 1]));
        assert_eq!(s.step(Some(&channel), now), None); // stale slot must not advance
        assert_eq!(s.step(Some(&[1, 2]), now), Some(vec![31, 2]));
        channel[1] = 2;
        assert_eq!(s.step(Some(&channel), now), None);
        assert!(matches!(s.stage, Stage::Done));
    }
    #[test]
    fn timeouts_do_not_block_capture_and_truncated_frames_do_not_panic() {
        let mut now = Instant::now();
        let mut s = Startup::new(now);
        assert_eq!(s.step(Some(&[5]), now), Some(vec![22, 3]));
        assert_eq!(s.step(Some(&[13]), now), None);
        now += Duration::from_secs(4);
        assert_eq!(s.step(None, now), Some(vec![64]));
        now += Duration::from_secs(4);
        assert_eq!(s.step(None, now), None);
        assert!(matches!(s.stage, Stage::Done));
    }
}
