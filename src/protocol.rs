//! MeshCore wire decoding. Unknown and malformed packets retain their original bytes.
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::ops::Range;

pub const MAX_FRAME: usize = 176; // companion MAX_FRAME_SIZE

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capture {
    pub at: DateTime<Local>,
    /// Complete companion frame, without the serial framing header.
    pub frame: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Decoded {
    pub kind: String,
    pub summary: String,
    pub fields: Vec<(String, String)>,
    pub warning: Option<String>,
    pub snr: Option<f32>,
    pub rssi: Option<i8>,
    pub hops: Option<usize>,
    pub path_width: Option<usize>,
    pub mesh_bytes: Option<usize>,
    pub route: Option<Route>,
    /// Payload range within the mesh packet (excluding companion RX metadata).
    pub payload_range: Option<Range<usize>>,
    pub scope: Option<Scope>,
    pub channel_hash: Option<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    ScopedFlood,
    Flood,
    Direct,
    ScopedDirect,
}
impl Route {
    pub fn name(self) -> &'static str {
        match self {
            Self::ScopedFlood => "Scoped flood",
            Self::Flood => "Flood",
            Self::Direct => "Direct",
            Self::ScopedDirect => "Scoped direct",
        }
    }
}
#[derive(Clone, Debug)]
pub struct Scope {
    pub code: u16,
    pub payload_type: u8,
    pub payload: Vec<u8>,
}
impl Decoded {
    /// Common list metadata, independent of payload type and catalogue annotations.
    pub fn radio_summary(&self) -> String {
        format!(
            "{} · {} B",
            self.route.map_or("Route —", Route::name),
            self.mesh_bytes.map_or("—".into(), |n| n.to_string())
        )
    }
    fn field(&mut self, key: &str, value: impl ToString) {
        self.fields.push((key.into(), value.to_string()));
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn decode(frame: &[u8]) -> Decoded {
    let mut d = Decoded::default();
    let Some(&code) = frame.first() else {
        d.kind = "Malformed".into();
        d.warning = Some("Empty companion frame".into());
        return d;
    };
    d.field("Companion type", format!("0x{code:02X}"));
    if code != 0x88 {
        d.kind = match code {
            0 => "OK",
            1 => "Device error",
            3 => "Contact",
            5 => "Self info",
            0x0d => "Device info",
            0x12 => "Channel info",
            0x1c => "Default region",
            0x80 | 0x8a => "Discovery",
            0x83 => "Message waiting",
            _ => "Companion",
        }
        .into();
        d.summary = format!("{} · {} bytes", d.kind, frame.len());
        d.field("Body", hex(&frame[1..]));
        if code == 1 {
            d.warning = Some(format!("Device returned error: {}", hex(&frame[1..])));
        }
        return d;
    }
    d.kind = "Malformed RX".into();
    d.mesh_bytes = frame.len().checked_sub(3);
    if frame.len() < 3 {
        d.warning = Some("Truncated RX log metadata".into());
        return d;
    }
    d.snr = Some(frame[1] as i8 as f32 / 4.0);
    d.rssi = Some(frame[2] as i8);
    d.field("SNR", format!("{:+.2} dB", d.snr.unwrap()));
    d.field("RSSI", format!("{} dBm", d.rssi.unwrap()));
    if let Err(e) = decode_mesh(&frame[3..], &mut d) {
        d.warning = Some(e.into());
        d.summary = format!("{} · malformed", d.kind);
    }
    d.summary.push_str(&format!(" · {} B", frame.len() - 3));
    d
}

fn decode_mesh(raw: &[u8], d: &mut Decoded) -> Result<(), &'static str> {
    let &header = raw.first().ok_or("Missing mesh header")?;
    let route = header & 3;
    let ty = (header >> 2) & 15;
    let version = header >> 6;
    d.kind = match ty {
        0 => "Request",
        1 => "Response",
        2 => "Direct text",
        3 => "ACK",
        4 => "Advert",
        5 => "Channel text",
        6 => "Channel data",
        7 => "Anonymous req",
        8 => "Path",
        9 => "Trace",
        10 => "Multipart",
        11 => "Control",
        15 => "Custom",
        _ => "Unknown",
    }
    .into();
    d.route = Some(match route {
        0 => Route::ScopedFlood,
        1 => Route::Flood,
        2 => Route::Direct,
        _ => Route::ScopedDirect,
    });
    let route_name = d.route.unwrap().name();
    d.field(
        "Header",
        format!("0x{header:02X} · version {} · {route_name}", version + 1),
    );
    let mut pos = 1;
    let mut scope_code = None;
    if route == 0 || route == 3 {
        let codes = raw.get(pos..pos + 4).ok_or("Truncated transport codes")?;
        d.field(
            "Transport codes",
            format!(
                "{:04X} / {:04X}",
                u16::from_le_bytes([codes[0], codes[1]]),
                u16::from_le_bytes([codes[2], codes[3]])
            ),
        );
        pos += 4;
        scope_code = Some(u16::from_le_bytes([codes[0], codes[1]]));
    }
    let path_len = *raw.get(pos).ok_or("Missing path length")?;
    pos += 1;
    let count = (path_len & 63) as usize;
    let width = (path_len >> 6) as usize + 1;
    if width == 4 || count * width > 64 {
        return Err("Invalid encoded path length");
    }
    let path = raw.get(pos..pos + count * width).ok_or("Truncated path")?;
    pos += count * width;
    d.hops = Some(count);
    d.path_width = Some(width);
    d.payload_range = Some(pos..raw.len());
    if ty == 9 {
        d.field(
            "Trace SNR samples",
            path.iter()
                .map(|v| format!("{:+.2}", *v as i8 as f32 / 4.0))
                .collect::<Vec<_>>()
                .join(" → "),
        );
    } else {
        d.field(
            "Path",
            if count == 0 {
                "No path entries".into()
            } else {
                format!(
                    "{} · {count} × {width}-byte hashes",
                    path.chunks(width).map(hex).collect::<Vec<_>>().join(" → ")
                )
            },
        );
    }
    let p = raw
        .get(pos..)
        .filter(|p| !p.is_empty())
        .ok_or("Missing payload")?;
    if p.len() > 184 {
        return Err("Payload exceeds MeshCore maximum");
    }
    d.field("Payload", format!("{} bytes · type 0x{ty:02X}", p.len()));
    d.summary = format!("{route_name} · {count} path entries");
    if version != 0 {
        d.warning =
            Some("Unsupported payload version; body preserved without interpretation".into());
        return Ok(());
    }
    d.scope = scope_code.map(|code| Scope {
        code,
        payload_type: ty,
        payload: p.to_vec(),
    });
    match ty {
        0 | 1 | 2 | 8 => {
            if p.len() < 5 {
                return Err("Truncated encrypted peer payload");
            }
            d.field("Destination hash", hex(&p[..1]));
            d.field("Source hash", hex(&p[1..2]));
            d.field("MAC", hex(&p[2..4]));
            d.field(
                "Content",
                format!("Encrypted · {} bytes · peer secret required", p.len() - 4),
            );
        }
        5 | 6 => {
            if p.len() < 4 {
                return Err("Truncated encrypted channel payload");
            }
            d.field("Channel hash", hex(&p[..1]));
            d.channel_hash = Some(p[0]);
            d.field("MAC", hex(&p[1..3]));
            d.field(
                "Content",
                format!("Encrypted · {} bytes · channel key required", p.len() - 3),
            );
            d.summary = format!("Channel {:02X} · {route_name} · {count} path entries", p[0]);
        }
        3 => {
            if p.len() != 4 {
                return Err("ACK must contain exactly four bytes");
            }
            d.field(
                "Acknowledgment",
                format!("0x{:08X}", u32::from_le_bytes(p.try_into().unwrap())),
            );
        }
        4 => {
            if p.len() < 100 {
                return Err("Truncated advertisement (key, timestamp, signature)");
            }
            d.field("Public key", hex(&p[..32]));
            d.field(
                "Advert timestamp",
                u32::from_le_bytes(p[32..36].try_into().unwrap()),
            );
            d.field("Signature", hex(&p[36..100]));
            d.field("Verification", "Signature not verified");
            d.field("Application data", hex(&p[100..]));
            if let Some(&flags) = p.get(100) {
                d.field(
                    "Node role",
                    match flags & 15 {
                        1 => "Companion",
                        2 => "Repeater",
                        3 => "Room server",
                        4 => "Sensor",
                        _ => "Unknown",
                    },
                );
                let mut offset = 101;
                if flags & 0x10 != 0 {
                    let coords = p
                        .get(offset..offset + 8)
                        .ok_or("Truncated advert coordinates")?;
                    let lat = i32::from_le_bytes(coords[..4].try_into().unwrap()) as f64 / 1e6;
                    let lon = i32::from_le_bytes(coords[4..].try_into().unwrap()) as f64 / 1e6;
                    d.field("Location (unverified)", format!("{lat:.6}, {lon:.6}"));
                    offset += 8;
                }
                for bit in [0x20, 0x40] {
                    if flags & bit != 0 {
                        p.get(offset..offset + 2)
                            .ok_or("Truncated advert feature field")?;
                        offset += 2;
                    }
                }
                if flags & 0x80 != 0 {
                    let bytes = p.get(offset..).ok_or("Truncated advert name")?;
                    let name = String::from_utf8_lossy(bytes)
                        .trim_end_matches('\0')
                        .to_string();
                    d.field("Name (unverified)", &name);
                    d.summary = format!("{name} · {route_name} · {count} path entries");
                }
            }
        }
        7 => {
            if p.len() < 36 {
                return Err("Truncated anonymous request");
            }
            d.field("Destination hash", hex(&p[..1]));
            d.field("Ephemeral public key", hex(&p[1..33]));
            d.field("MAC", hex(&p[33..35]));
            d.field("Content", "Encrypted · recipient secret required");
        }
        9 => {
            if p.len() < 9 {
                return Err("Truncated trace payload");
            }
            d.field("Trace tag", hex(&p[..4]));
            d.field("Auth code", hex(&p[4..8]));
            d.field("Flags", format!("0x{:02X}", p[8]));
            d.field("Trace data", hex(&p[9..]));
        }
        _ => {
            d.field("Body", hex(p));
        }
    }
    Ok(())
}

/// Incremental serial/TCP deframer. Discards noise and rejects oversized lengths.
#[derive(Default)]
pub struct Deframer {
    bytes: Vec<u8>,
}
impl Deframer {
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        self.bytes.extend_from_slice(bytes);
        let mut frames = Vec::new();
        loop {
            let Some(start) = self.bytes.iter().position(|&b| b == b'>') else {
                self.bytes.clear();
                break;
            };
            self.bytes.drain(..start);
            if self.bytes.len() < 3 {
                break;
            }
            let len = u16::from_le_bytes([self.bytes[1], self.bytes[2]]) as usize;
            if len == 0 || len > MAX_FRAME {
                self.bytes.remove(0);
                continue;
            }
            if self.bytes.len() < len + 3 {
                break;
            }
            frames.push(self.bytes[3..len + 3].to_vec());
            self.bytes.drain(..len + 3);
        }
        frames
    }
}

#[cfg(test)]
pub fn sample_frame(n: usize) -> Vec<u8> {
    let ty = [4, 5, 2, 3, 6, 9][n % 6];
    let hops = n % 4;
    let mut f = vec![
        0x88,
        (12 - (n % 32) as i8) as u8,
        (-75 - (n % 35) as i8) as u8,
        (ty << 2) | 1,
        hops as u8,
    ];
    f.extend((0..hops).map(|i| (i * 37 + n) as u8));
    match ty {
        4 => {
            f.extend((0..100).map(|i| (i + n) as u8));
            f.extend_from_slice(b"\x82Test repeater");
        }
        3 => f.extend_from_slice(&(n as u32).to_le_bytes()),
        9 => f.extend_from_slice(&[1, 2, 3, 4, 0, 0, 0, 0, 0, 0x42]),
        _ => f.extend((0..19).map(|i| (i * 17 + n) as u8)),
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_handles_noise_fragmentation_and_multiple_frames() {
        let mut f = Deframer::default();
        assert!(f.feed(b"noise>\xFF\xFF>\x03").is_empty());
        assert_eq!(
            f.feed(&[0, 0x88, 4, 180, b'>', 1, 0, 0]),
            vec![vec![0x88, 4, 180], vec![0]]
        );
    }
    #[test]
    fn signed_radio_metrics_and_multibyte_path() {
        let d = decode(&[0x88, 0xf8, 0xa0, 0x15, 0x42, 1, 2, 3, 4, 0xab, 1, 2, 3]);
        assert_eq!(d.snr, Some(-2.0));
        assert_eq!(d.rssi, Some(-96));
        assert_eq!(d.hops, Some(2));
        assert_eq!(d.path_width, Some(2));
        assert!(d.warning.is_none());
        assert!(d.fields.iter().any(|(_, v)| v.contains("01 02 → 03 04")));
    }
    #[test]
    fn scoped_route_and_reserved_version() {
        let d = decode(&[0x88, 0, 0, 0x4c, 0x34, 0x12, 0x78, 0x56, 0, 1, 2, 3, 4]);
        assert!(d.fields.iter().any(|(_, v)| v == "1234 / 5678"));
        assert!(d.warning.unwrap().contains("Unsupported"));
    }
    #[test]
    fn arbitrary_short_inputs_never_panic() {
        for len in 0..260 {
            for byte in 0..=255 {
                let _ = decode(&vec![byte; len]);
            }
        }
        for n in 0..50 {
            let f = sample_frame(n);
            for len in 0..=f.len() {
                let _ = decode(&f[..len]);
            }
        }
    }
    #[test]
    fn rejects_invalid_path_and_truncated_payload() {
        assert!(decode(&[0x88, 0, 0, 0x11, 0xc0]).warning.is_some());
        assert!(decode(&[0x88, 0, 0, 0x11, 0, 1]).warning.is_some());
    }
    #[test]
    fn list_metadata_is_uniform_across_all_payload_types_and_routes() {
        for ty in 0..16 {
            for (route, name) in [
                (0, "Scoped flood"),
                (1, "Flood"),
                (2, "Direct"),
                (3, "Scoped direct"),
            ] {
                let mut frame = vec![0x88, 4, 0xa0, (ty << 2) | route];
                if route == 0 || route == 3 {
                    frame.extend_from_slice(&[0x34, 0x12, 0, 0]);
                }
                frame.extend_from_slice(&[0x41, 7, 9]); // one two-byte path entry
                frame.extend(vec![0; if ty == 3 { 4 } else { 110 }]);
                let d = decode(&frame);
                assert_eq!(d.hops, Some(1));
                assert_eq!(d.path_width, Some(2));
                assert_eq!(d.radio_summary(), format!("{name} · {} B", frame.len() - 3));
            }
        }
    }
    #[test]
    fn malformed_rx_keeps_available_list_metadata_and_placeholders() {
        let d = decode(&[0x88]);
        assert!(d.warning.is_some());
        assert_eq!(d.radio_summary(), "Route — · — B");
        let d = decode(&[0x88, 0, 150, 0x11, 0, 1]); // truncated advert payload
        assert!(d.warning.is_some());
        assert_eq!(d.radio_summary(), "Flood · 3 B");
        assert_eq!(d.hops, Some(0));
        assert_eq!(d.path_width, Some(1));
    }
}
