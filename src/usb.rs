//! USB metadata identifies hardware, so confirm the running companion protocol.
use crate::protocol::Deframer;
use anyhow::{Context, Result};
use std::{
    io::{self, Read, Write},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct Device {
    pub port: String,
    pub description: String,
}
struct PortState {
    identity: String,
    generation: u64,
    retry_at: Instant,
    description: Option<String>,
    unavailable: bool,
}
#[derive(Default)]
struct Ports {
    entries: std::collections::BTreeMap<String, PortState>,
    generation: u64,
}
impl Ports {
    fn refresh(&mut self, present: Vec<(String, String)>, now: Instant) {
        self.entries
            .retain(|port, _| present.iter().any(|(p, _)| p == port));
        for (port, identity) in present {
            if self
                .entries
                .get(&port)
                .is_none_or(|p| p.identity != identity)
            {
                self.generation += 1;
                self.entries.insert(
                    port,
                    PortState {
                        identity,
                        generation: self.generation,
                        retry_at: now,
                        description: None,
                        unavailable: false,
                    },
                );
            }
        }
    }
    fn next_probe(&self, now: Instant) -> Option<(String, u64)> {
        self.entries
            .iter()
            .find(|(_, p)| p.description.is_none() && p.retry_at <= now)
            .map(|(port, p)| (port.clone(), p.generation))
    }
    fn verified(
        &mut self,
        port: &str,
        generation: u64,
        result: Result<Option<String>>,
        now: Instant,
    ) {
        if let Some(state) = self
            .entries
            .get_mut(port)
            .filter(|s| s.generation == generation)
        {
            state.unavailable = result.is_err();
            state.description = result.ok().flatten();
            state.retry_at = now + Duration::from_secs(10);
        }
    }
    fn devices(&self) -> Vec<Device> {
        self.entries
            .iter()
            .filter_map(|(port, p)| {
                p.description.as_ref().map(|description| Device {
                    port: port.clone(),
                    description: description.clone(),
                })
            })
            .collect()
    }
}

/// Enumerate continuously; probe new ports off the watcher thread so unplugging is immediate.
pub fn watch(baud: u32, stop: &AtomicBool, mut update: impl FnMut(Vec<Device>, String)) {
    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::channel::<(String, u64, Result<Option<String>>)>();
        let mut ports = Ports::default();
        let mut job: Option<std::thread::ScopedJoinHandle<'_, ()>> = None;
        while !stop.load(Ordering::Relaxed) {
            let enumeration = serialport::available_ports().context("Enumerating USB serial ports");
            let error = match enumeration {
                Ok(present) => {
                    ports.refresh(
                        present
                            .into_iter()
                            .filter(|p| {
                                matches!(p.port_type, serialport::SerialPortType::UsbPort(_))
                            })
                            .map(|p| (p.port_name, format!("{:?}", p.port_type)))
                            .collect(),
                        Instant::now(),
                    );
                    None
                }
                Err(e) => {
                    ports.refresh(vec![], Instant::now());
                    Some(format!("USB: {e:#} · retrying"))
                }
            };
            if let Ok((port, generation, result)) = rx.try_recv() {
                if let Some(handle) = job.take() {
                    let _ = handle.join();
                }
                ports.verified(&port, generation, result, Instant::now());
            }
            if job.is_none()
                && let Some((port, generation)) = ports.next_probe(Instant::now())
            {
                let tx = tx.clone();
                job = Some(scope.spawn(move || {
                    let result = (|| -> Result<Option<String>> {
                        let mut connection = serialport::new(&port, baud)
                            .timeout(Duration::from_millis(100))
                            .open()?;
                        probe(&mut connection, Duration::from_secs(3), stop)
                    })();
                    let _ = tx.send((port, generation, result));
                }));
            }
            let devices = ports.devices();
            let unavailable = ports.entries.values().filter(|p| p.unavailable).count();
            let status = error.unwrap_or_else(|| {
                format!(
                    "USB: {} companions · {} ports unavailable · {}",
                    devices.len(),
                    unavailable,
                    if job.is_some() {
                        "checking new ports"
                    } else {
                        "watching"
                    }
                )
            });
            update(devices, status);
            for _ in 0..5 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    });
}

fn probe(
    port: &mut (impl Read + Write),
    duration: Duration,
    stop: &AtomicBool,
) -> Result<Option<String>> {
    let deadline = Instant::now() + duration;
    let mut next_query = Instant::now();
    let mut deframer = Deframer::default();
    let mut bytes = [0; 512];
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        if Instant::now() >= next_query {
            // DEVICE_QUERY v3 reads firmware/board info; no radio or persistent writes.
            port.write_all(&[b'<', 2, 0, 0x16, 3])?;
            port.flush()?;
            next_query = Instant::now() + Duration::from_millis(650);
        }
        match port.read(&mut bytes) {
            Ok(0) => break,
            Ok(n) => {
                for frame in deframer.feed(&bytes[..n]) {
                    if let Some(description) = device_info(&frame) {
                        return Ok(Some(description));
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(None)
}

fn device_info(frame: &[u8]) -> Option<String> {
    // Stable v3 fields: response/version/capacities/PIN/build[12]/board[40]/version[20].
    if frame.len() < 80 || frame[0] != 0x0d || frame[1] == 0 {
        return None;
    }
    let text = |bytes: &[u8]| -> Option<String> {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let text = std::str::from_utf8(&bytes[..end]).ok()?.trim();
        (!text.is_empty() && text.chars().all(|c| !c.is_control())).then(|| text.to_string())
    };
    let board = text(&frame[20..60])?;
    let version = text(&frame[60..80])?;
    Some(format!("{board} · firmware {version}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    #[test]
    fn unplugging_removes_ports_and_late_probe_results_cannot_restore_them() {
        let now = Instant::now();
        let mut ports = Ports::default();
        ports.refresh(vec![("usb".into(), "radio".into())], now);
        let (port, generation) = ports.next_probe(now).unwrap();
        ports.verified(&port, generation, Ok(Some("MeshCore".into())), now);
        assert_eq!(ports.devices().len(), 1);
        ports.refresh(vec![], now);
        assert!(ports.devices().is_empty());
        ports.refresh(vec![("usb".into(), "different device".into())], now);
        ports.verified(&port, generation, Ok(Some("old result".into())), now);
        assert!(ports.devices().is_empty());
        assert!(ports.next_probe(now).is_some());
    }
    #[test]
    fn unidentified_ports_are_retried_after_boot_and_verified_ports_are_left_alone() {
        let now = Instant::now();
        let mut ports = Ports::default();
        ports.refresh(vec![("usb".into(), "radio".into())], now);
        let (port, generation) = ports.next_probe(now).unwrap();
        ports.verified(&port, generation, Ok(None), now);
        assert!(ports.next_probe(now + Duration::from_secs(1)).is_none());
        assert!(ports.next_probe(now + Duration::from_secs(10)).is_some());
        ports.verified(&port, generation, Ok(Some("MeshCore".into())), now);
        assert!(ports.next_probe(now + Duration::from_secs(20)).is_none());
    }
    struct Port {
        reads: VecDeque<Vec<u8>>,
        written: Vec<u8>,
    }
    impl Read for Port {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let Some(bytes) = self.reads.pop_front() else {
                return Ok(0);
            };
            buf[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }
    impl Write for Port {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn reply() -> Vec<u8> {
        let mut reply = vec![0; 80];
        reply[0] = 0x0d;
        reply[1] = 3;
        reply[20..26].copy_from_slice(b"Heltec");
        reply[60..65].copy_from_slice(b"v1.12");
        reply
    }
    #[test]
    fn identifies_companion_from_fragmented_response_among_noise() {
        let mut response = vec![b'>', 80, 0];
        response.extend(reply());
        let mut port = Port {
            reads: VecDeque::from([
                b"boot log".to_vec(),
                vec![b'>', 1, 0, 0],
                response[..9].to_vec(),
                response[9..].to_vec(),
            ]),
            written: vec![],
        };
        assert_eq!(
            probe(&mut port, Duration::from_secs(1), &AtomicBool::new(false))
                .unwrap()
                .as_deref(),
            Some("Heltec · firmware v1.12")
        );
        assert_eq!(port.written, [b'<', 2, 0, 0x16, 3]);
    }
    #[test]
    fn ignores_other_protocols_and_truncated_or_invalid_info() {
        assert!(device_info(b"MeshCore").is_none());
        let mut bad = reply();
        bad[0] = 5;
        assert!(device_info(&bad).is_none());
        let mut bad = reply();
        bad[60] = 0;
        assert!(device_info(&bad).is_none());
        let mut port = Port {
            reads: VecDeque::from([b"unrelated serial device".to_vec()]),
            written: vec![],
        };
        assert!(
            probe(&mut port, Duration::from_secs(1), &AtomicBool::new(false))
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn cancelled_scan_does_not_write() {
        let mut port = Port {
            reads: VecDeque::new(),
            written: vec![],
        };
        assert!(
            probe(&mut port, Duration::from_secs(1), &AtomicBool::new(true))
                .unwrap()
                .is_none()
        );
        assert!(port.written.is_empty());
    }
}
