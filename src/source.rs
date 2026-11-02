use crate::protocol::{Capture, Deframer};
use anyhow::{Context, Result};
use chrono::Local;
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::SyncSender,
    },
    thread,
    time::{Duration, Instant},
};

pub enum Event {
    Packet(Capture),
    Status(String),
}
#[derive(Clone)]
pub enum Source {
    Serial(String, u32),
    Tcp(String),
    Ble(crate::ble::Device),
}
pub struct Worker {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
trait Connection: Read + Write + Send {}
impl<T: Read + Write + Send> Connection for T {}
fn command(connection: &mut dyn Connection, payload: &[u8]) -> Result<()> {
    let len = (payload.len() as u16).to_le_bytes();
    connection.write_all(&[b'<', len[0], len[1]])?;
    connection.write_all(payload)?;
    connection.flush()?;
    Ok(())
}

pub fn start(source: Source, tx: SyncSender<Event>) -> Result<Worker> {
    if let Source::Ble(device) = source {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handle = thread::spawn(move || {
            let result = crate::ble::runtime().and_then(|rt| {
                rt.block_on(async {
                    use btleplug::api::Peripheral as _;
                    let peripheral = device.peripheral.clone();
                    let result = {
                        let listening = Box::pin(crate::ble::listen(device, &tx, &flag));
                        let cancelled = Box::pin(async {
                            while !flag.load(Ordering::Relaxed) {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        });
                        match futures_util::future::select(listening, cancelled).await {
                            futures_util::future::Either::Left((result, _)) => result,
                            futures_util::future::Either::Right(_) => Ok(()),
                        }
                    };
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), peripheral.disconnect()).await;
                    result
                })
            });
            if let Err(e) = result {
                let _ = tx.try_send(Event::Status(format!(
                    "BLE error: {e:#} · Esc to choose another device"
                )));
            }
        });
        return Ok(Worker {
            stop,
            handle: Some(handle),
        });
    }
    let mut connection: Box<dyn Connection> = match &source {
        Source::Ble(_) => unreachable!(),
        Source::Serial(port, baud) => Box::new(
            serialport::new(port, *baud)
                .timeout(Duration::from_millis(100))
                .open()
                .with_context(|| format!("Opening serial port {port}"))?,
        ),
        Source::Tcp(addr) => {
            use std::net::ToSocketAddrs;
            let addresses = addr
                .to_socket_addrs()
                .with_context(|| format!("Resolving {addr}"))?;
            let mut socket = None;
            for address in addresses {
                if let Ok(s) = TcpStream::connect_timeout(&address, Duration::from_secs(3)) {
                    socket = Some(s);
                    break;
                }
            }
            let stream = socket.context("Could not connect to companion TCP address")?;
            stream.set_read_timeout(Some(Duration::from_millis(100)))?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            Box::new(stream)
        }
    };
    command(&mut *connection, &crate::companion::app_start()).context("Sending APP_START")?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let handle = thread::spawn(move || {
        let mut decoder = Deframer::default();
        let mut bytes = [0; 1024];
        let mut dropped = 0usize;
        let mut startup = crate::companion::Startup::new(Instant::now());
        while !flag.load(Ordering::Relaxed) {
            let frames = match connection.read(&mut bytes) {
                Ok(0) => {
                    let _ =
                        tx.try_send(Event::Status("Disconnected · restart to reconnect".into()));
                    break;
                }
                Ok(count) => decoder.feed(&bytes[..count]),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    vec![]
                }
                Err(e) => {
                    let _ = tx.try_send(Event::Status(format!("Connection error: {e}")));
                    break;
                }
            };
            for frame in frames {
                if let Some(payload) = startup.step(Some(&frame), Instant::now())
                    && let Err(e) = command(&mut *connection, &payload)
                {
                    let _ = tx.try_send(Event::Status(format!("Companion query failed: {e}")));
                    return;
                }
                match tx.try_send(Event::Packet(Capture {
                    at: Local::now(),
                    frame,
                })) {
                    Ok(()) => {}
                    Err(std::sync::mpsc::TrySendError::Full(_)) => dropped += 1,
                    Err(_) => return,
                }
            }
            if let Some(payload) = startup.step(None, Instant::now())
                && let Err(e) = command(&mut *connection, &payload)
            {
                let _ = tx.try_send(Event::Status(format!("Companion query failed: {e}")));
                break;
            }
            if let Some(notice) = startup.notice.take() {
                let _ = tx.try_send(Event::Status(notice));
            }
            if dropped > 0
                && tx
                    .try_send(Event::Status(format!(
                        "Capture overloaded · {dropped} frames dropped"
                    )))
                    .is_ok()
            {
                dropped = 0;
            }
        }
    });
    Ok(Worker {
        stop,
        handle: Some(handle),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tcp_startup_queries_are_framed_and_metadata_and_rx_are_forwarded() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            fn read_command(stream: &mut TcpStream) -> Vec<u8> {
                let mut header = [0; 3];
                stream.read_exact(&mut header).unwrap();
                assert_eq!(header[0], b'<');
                let mut bytes = vec![0; u16::from_le_bytes([header[1], header[2]]) as usize];
                stream.read_exact(&mut bytes).unwrap();
                bytes
            }
            fn reply(stream: &mut TcpStream, bytes: &[u8]) {
                let len = (bytes.len() as u16).to_le_bytes();
                // Separate header/payload writes exercise incremental deframing.
                stream.write_all(&[b'>', len[0], len[1]]).unwrap();
                stream.write_all(bytes).unwrap();
            }
            assert_eq!(read_command(&mut stream), crate::companion::app_start());
            reply(&mut stream, &[5]);
            assert_eq!(read_command(&mut stream), [22, 3]);
            let mut info = vec![0; 80];
            info[..4].copy_from_slice(&[13, 14, 100, 2]);
            reply(&mut stream, &info);
            assert_eq!(read_command(&mut stream), [64]);
            let mut scope = vec![0; 48];
            scope[0] = 28;
            scope[1..6].copy_from_slice(b"#test");
            scope[32..].fill(42);
            reply(&mut stream, &scope);
            assert_eq!(read_command(&mut stream), [31, 0]);
            reply(&mut stream, &crate::protocol::sample_frame(0));
            let mut channel = vec![0; 50];
            channel[0] = 18;
            channel[2..8].copy_from_slice(b"Public");
            channel[34..].fill(42);
            reply(&mut stream, &channel);
            assert_eq!(read_command(&mut stream), [31, 1]);
            let mut empty = vec![0; 50];
            empty[0] = 18;
            empty[1] = 1;
            reply(&mut stream, &empty);
        });
        let (tx, rx) = std::sync::mpsc::sync_channel(32);
        let worker = start(Source::Tcp(address), tx).unwrap();
        let mut codes = vec![];
        while codes.len() < 6 {
            match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::Packet(packet) => codes.push(packet.frame[0]),
                Event::Status(_) => {}
            }
        }
        drop(worker);
        server.join().unwrap();
        assert_eq!(codes, [5, 13, 28, 0x88, 18, 18]);
    }
}
