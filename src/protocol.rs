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
    /// Parsing tree in wire order. Ranges are absolute offsets in Capture::frame.
    pub structure: Vec<WireField>,
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

#[derive(Clone, Debug)]
pub struct WireField {
    pub name: String,
    pub range: Range<usize>,
    pub interpretation: String,
    /// Subfield bit indices, least significant bit first, end exclusive.
    pub bits: Option<Range<u8>>,
    pub children: Vec<WireField>,
}
impl WireField {
    fn new(name: impl Into<String>, range: Range<usize>, value: impl ToString) -> Self {
        Self {
            name: name.into(),
            range,
            interpretation: value.to_string(),
            bits: None,
            children: vec![],
        }
    }
    fn bit(name: &str, offset: usize, bits: Range<u8>, value: impl ToString) -> Self {
        Self {
            bits: Some(bits),
            ..Self::new(name, offset..offset + 1, value)
        }
    }
}

/// Records every consumed byte, including partial fields when parsing fails.
struct WireReader<'a> {
    bytes: &'a [u8],
    base: usize,
    pos: usize,
    fields: Vec<WireField>,
}
impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8], base: usize) -> Self {
        Self {
            bytes,
            base,
            pos: 0,
            fields: vec![],
        }
    }
    fn read(&mut self, name: &str, length: usize) -> Result<&'a [u8], &'static str> {
        let start = self.pos;
        self.pos = self.pos.saturating_add(length).min(self.bytes.len());
        let available = self.pos - start;
        let partial = available < length;
        self.fields.push(WireField::new(
            name,
            self.base + start..self.base + self.pos,
            if partial {
                format!("Truncated: expected {length} B, got {available} B")
            } else {
                String::new()
            },
        ));
        if partial {
            Err("Truncated field")
        } else {
            Ok(&self.bytes[start..self.pos])
        }
    }
    fn value(&mut self, value: impl ToString) {
        self.fields.last_mut().unwrap().interpretation = value.to_string();
    }
    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
    fn rest(&mut self, name: &str, value: &str) -> &'a [u8] {
        let bytes = self.read(name, self.remaining()).unwrap();
        self.value(value);
        bytes
    }
    fn preserve_remainder(&mut self) {
        if self.remaining() > 0 {
            self.rest("Undecoded bytes", "Not interpreted");
        }
    }
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
    d.structure
        .push(WireField::new("Companion type", 0..1, "Raw RX log"));
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
        d.structure[0].interpretation = d.kind.clone();
        d.summary = format!("{} · {} bytes", d.kind, frame.len());
        d.field("Body", hex(&frame[1..]));
        d.structure.push(WireField::new(
            "Body",
            1..frame.len(),
            "Companion body · not interpreted",
        ));
        if code == 1 {
            d.warning = Some(format!("Device returned error: {}", hex(&frame[1..])));
        }
        return d;
    }
    d.kind = "Malformed RX".into();
    d.mesh_bytes = frame.len().checked_sub(3);
    if let Some(&snr) = frame.get(1) {
        d.snr = Some(snr as i8 as f32 / 4.0);
        let value = format!("{:+.2} dB (i8 / 4)", d.snr.unwrap());
        d.structure.push(WireField::new("SNR", 1..2, value));
        d.field("SNR", format!("{:+.2} dB", d.snr.unwrap()));
    }
    if let Some(&rssi) = frame.get(2) {
        d.rssi = Some(rssi as i8);
        d.structure.push(WireField::new(
            "RSSI",
            2..3,
            format!("{} dBm (i8)", d.rssi.unwrap()),
        ));
        d.field("RSSI", format!("{} dBm", d.rssi.unwrap()));
    }
    if frame.len() < 3 {
        d.warning = Some("Truncated RX log metadata".into());
        return d;
    }
    if let Err(e) = decode_mesh(&frame[3..], &mut d) {
        d.warning = Some(e.into());
        d.summary = format!("{} · malformed", d.kind);
    }
    d.summary.push_str(&format!(" · {} B", frame.len() - 3));
    d
}

fn decode_mesh(raw: &[u8], d: &mut Decoded) -> Result<(), &'static str> {
    let mut reader = WireReader::new(raw, 3);
    let result = decode_packet(&mut reader, d);
    if reader.remaining() > 0 {
        reader.rest(
            "Unparsed remainder",
            "Payload boundary unknown; not interpreted",
        );
    }
    d.structure.extend(reader.fields);
    result
}

fn decode_packet(r: &mut WireReader<'_>, d: &mut Decoded) -> Result<(), &'static str> {
    let header = r.read("Header", 1).map_err(|_| "Missing mesh header")?[0];
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
    let header_offset = r.fields.last().unwrap().range.start;
    r.fields.last_mut().unwrap().children = vec![
        WireField::bit("Route type", header_offset, 0..2, route_name),
        WireField::bit(
            "Payload type",
            header_offset,
            2..6,
            format!("0x{ty:02X} · {}", d.kind),
        ),
        WireField::bit(
            "Payload version",
            header_offset,
            6..8,
            format!(
                "v{}{}",
                version + 1,
                if version == 0 { "" } else { " · unsupported" }
            ),
        ),
    ];
    let mut scope_code = None;
    if route == 0 || route == 3 {
        let codes = r
            .read("Transport codes", 4)
            .map_err(|_| "Truncated transport codes")?;
        let start = r.fields.last().unwrap().range.start;
        let first = u16::from_le_bytes([codes[0], codes[1]]);
        let second = u16::from_le_bytes([codes[2], codes[3]]);
        d.field("Transport codes", format!("{first:04X} / {second:04X}"));
        r.fields.last_mut().unwrap().children = vec![
            WireField::new(
                "Code 1",
                start..start + 2,
                format!("0x{first:04X} · region scope (u16 LE)"),
            ),
            WireField::new(
                "Code 2",
                start + 2..start + 4,
                format!("0x{second:04X} · reserved (u16 LE)"),
            ),
        ];
        scope_code = Some(first);
    }
    let path_len = r
        .read("Path length", 1)
        .map_err(|_| "Missing path length")?[0];
    let count = (path_len & 63) as usize;
    let width = (path_len >> 6) as usize + 1;
    let length_offset = r.fields.last().unwrap().range.start;
    r.fields.last_mut().unwrap().children = vec![
        WireField::bit("Entry count", length_offset, 0..6, count),
        WireField::bit(
            "Entry width",
            length_offset,
            6..8,
            format!(
                "{width} B{}",
                if width == 4 {
                    " · reserved / invalid"
                } else {
                    ""
                }
            ),
        ),
    ];
    if width == 4 || count * width > 64 {
        return Err("Invalid encoded path length");
    }
    let path = r
        .read("Path", count * width)
        .map_err(|_| "Truncated path")?;
    let start = r.fields.last().unwrap().range.start;
    r.value(format!(
        "{count} × {width} B{}",
        if count == 0 {
            " · empty"
        } else if ty == 9 {
            " · signal samples"
        } else {
            " · node hashes"
        }
    ));
    r.fields.last_mut().unwrap().children = path
        .chunks(if ty == 9 { 1 } else { width })
        .enumerate()
        .map(|(i, bytes)| {
            let size = bytes.len();
            WireField::new(
                format!("{} {}", if ty == 9 { "SNR sample" } else { "Hash" }, i + 1),
                start + i * size..start + (i + 1) * size,
                if ty == 9 {
                    format!("{:+.2} dB (i8 / 4)", bytes[0] as i8 as f32 / 4.0)
                } else {
                    String::new()
                },
            )
        })
        .collect();
    d.hops = Some(count);
    d.path_width = Some(width);
    d.payload_range = Some(r.pos..r.bytes.len());
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
    let p = r.rest("Payload", "");
    if p.is_empty() {
        r.value("Missing payload");
        return Err("Missing payload");
    }
    if p.len() > 184 {
        r.value("Payload exceeds MeshCore maximum; not interpreted");
        return Err("Payload exceeds MeshCore maximum");
    }
    d.field("Payload", format!("{} bytes · type 0x{ty:02X}", p.len()));
    d.summary = format!("{route_name} · {count} path entries");
    if version != 0 {
        r.value("Unsupported version; not interpreted");
        d.warning =
            Some("Unsupported payload version; body preserved without interpretation".into());
        return Ok(());
    }
    d.scope = scope_code.map(|code| Scope {
        code,
        payload_type: ty,
        payload: p.to_vec(),
    });
    let mut payload = WireReader::new(p, r.fields.last().unwrap().range.start);
    let result = decode_payload(&mut payload, d, ty);
    payload.preserve_remainder();
    r.fields.last_mut().unwrap().children = payload.fields;
    result
}

fn decode_payload(r: &mut WireReader<'_>, d: &mut Decoded, ty: u8) -> Result<(), &'static str> {
    match ty {
        0 | 1 | 2 | 8 => {
            let dst = r
                .read("Destination hash", 1)
                .map_err(|_| "Truncated encrypted peer payload")?;
            d.field("Destination hash", hex(dst));
            r.value("Destination public-key prefix");
            let src = r
                .read("Source hash", 1)
                .map_err(|_| "Truncated encrypted peer payload")?;
            d.field("Source hash", hex(src));
            r.value("Source public-key prefix");
            let mac = r
                .read("MAC", 2)
                .map_err(|_| "Truncated encrypted peer payload")?;
            d.field("MAC", hex(mac));
            r.value("Cipher MAC · not verified");
            ciphertext(r, d, "peer secret", "Truncated encrypted peer payload")?;
        }
        5 | 6 => {
            let hash = r
                .read("Channel hash", 1)
                .map_err(|_| "Truncated encrypted channel payload")?[0];
            d.field("Channel hash", format!("{hash:02X}"));
            d.channel_hash = Some(hash);
            r.value("First byte of SHA256(channel key)");
            let mac = r
                .read("MAC", 2)
                .map_err(|_| "Truncated encrypted channel payload")?;
            d.field("MAC", hex(mac));
            r.value("Cipher MAC · not verified");
            ciphertext(r, d, "channel key", "Truncated encrypted channel payload")?;
            d.summary = format!(
                "Channel {hash:02X} · {} · {} path entries",
                d.route.unwrap().name(),
                d.hops.unwrap()
            );
        }
        3 => {
            let valid_length = r.remaining() == 4;
            let bytes = r
                .read("Acknowledgment", 4)
                .map_err(|_| "ACK must contain exactly four bytes")?;
            let value = u32::from_le_bytes(bytes.try_into().unwrap());
            d.field("Acknowledgment", format!("0x{value:08X}"));
            r.value(format!("0x{value:08X} (u32 LE)"));
            if !valid_length {
                return Err("ACK must contain exactly four bytes");
            }
        }
        4 => {
            let key = r
                .read("Public key", 32)
                .map_err(|_| "Truncated advertisement (key, timestamp, signature)")?;
            d.field("Public key", hex(key));
            r.value("Ed25519 · unverified");
            let bytes = r
                .read("Advert timestamp", 4)
                .map_err(|_| "Truncated advertisement (key, timestamp, signature)")?;
            let timestamp = u32::from_le_bytes(bytes.try_into().unwrap());
            d.field("Advert timestamp", timestamp);
            let date = chrono::DateTime::from_timestamp(timestamp.into(), 0).unwrap();
            r.value(format!(
                "{} · {timestamp} (u32 LE)",
                date.format("%Y-%m-%d %H:%M:%S UTC")
            ));
            let signature = r
                .read("Signature", 64)
                .map_err(|_| "Truncated advertisement (key, timestamp, signature)")?;
            d.field("Signature", hex(signature));
            d.field("Verification", "Signature not verified");
            r.value("Ed25519 · signature not verified");
            let bytes = r.rest("Application data", "Unverified");
            d.field("Application data", hex(bytes));
            let mut app = WireReader::new(bytes, r.fields.last().unwrap().range.start);
            let result = decode_advert_app(&mut app, d);
            app.preserve_remainder();
            r.fields.last_mut().unwrap().children = app.fields;
            result?;
        }
        7 => {
            let dst = r
                .read("Destination hash", 1)
                .map_err(|_| "Truncated anonymous request")?;
            d.field("Destination hash", hex(dst));
            r.value("Destination public-key prefix");
            let key = r
                .read("Sender public key", 32)
                .map_err(|_| "Truncated anonymous request")?;
            d.field("Sender public key", hex(key));
            r.value("Sender's Ed25519 public key");
            let mac = r
                .read("MAC", 2)
                .map_err(|_| "Truncated anonymous request")?;
            d.field("MAC", hex(mac));
            r.value("Cipher MAC · not verified");
            ciphertext(r, d, "recipient secret", "Truncated anonymous request")?;
        }
        9 => {
            let tag = r
                .read("Trace tag", 4)
                .map_err(|_| "Truncated trace payload")?;
            d.field("Trace tag", hex(tag));
            let auth = r
                .read("Auth code", 4)
                .map_err(|_| "Truncated trace payload")?;
            d.field("Auth code", hex(auth));
            r.value("Authentication code · not verified");
            let flags = r.read("Flags", 1).map_err(|_| "Truncated trace payload")?[0];
            d.field("Flags", format!("0x{flags:02X}"));
            r.value(format!("0b{flags:08b}"));
            let data = r.rest("Trace data", "Not interpreted");
            d.field("Trace data", hex(data));
        }
        _ => {
            let body = r.rest("Body", "Not interpreted");
            d.field("Body", hex(body));
        }
    }
    Ok(())
}

fn ciphertext(
    r: &mut WireReader<'_>,
    d: &mut Decoded,
    secret: &str,
    error: &'static str,
) -> Result<(), &'static str> {
    let size = r.remaining();
    r.read("Ciphertext", size.max(1)).map_err(|_| error)?;
    let interpretation = format!("Encrypted · {size} bytes · {secret} required");
    r.value(&interpretation);
    d.field("Content", interpretation);
    Ok(())
}

fn decode_advert_app(r: &mut WireReader<'_>, d: &mut Decoded) -> Result<(), &'static str> {
    if r.remaining() == 0 {
        return Ok(());
    }
    let flags = r.read("Flags", 1)?[0];
    let offset = r.fields.last().unwrap().range.start;
    let role = match flags & 15 {
        1 => "Companion",
        2 => "Repeater",
        3 => "Room server",
        4 => "Sensor",
        _ => "Unknown",
    };
    d.field("Node role", role);
    r.fields.last_mut().unwrap().children = vec![WireField::bit("Node role", offset, 0..4, role)];
    for (bit, name) in [
        (4, "Location present"),
        (5, "Feature 1 present"),
        (6, "Feature 2 present"),
        (7, "Name present"),
    ] {
        r.fields.last_mut().unwrap().children.push(WireField::bit(
            name,
            offset,
            bit..bit + 1,
            if flags & (1 << bit) != 0 { "yes" } else { "no" },
        ));
    }
    if flags & 0x10 != 0 {
        let lat = r
            .read("Latitude", 4)
            .map_err(|_| "Truncated advert coordinates")?;
        let lat_raw = i32::from_le_bytes(lat.try_into().unwrap());
        let lat = lat_raw as f64 / 1e6;
        r.value(format!("{lat:.6}° · {lat_raw} (i32 LE / 10⁶) · unverified"));
        let lon = r
            .read("Longitude", 4)
            .map_err(|_| "Truncated advert coordinates")?;
        let lon_raw = i32::from_le_bytes(lon.try_into().unwrap());
        let lon = lon_raw as f64 / 1e6;
        r.value(format!("{lon:.6}° · {lon_raw} (i32 LE / 10⁶) · unverified"));
        d.field("Location (unverified)", format!("{lat:.6}, {lon:.6}"));
    }
    for (bit, name) in [(0x20, "Feature 1"), (0x40, "Feature 2")] {
        if flags & bit != 0 {
            let bytes = r
                .read(name, 2)
                .map_err(|_| "Truncated advert feature field")?;
            d.field(name, hex(bytes));
            r.value("Reserved for future use");
        }
    }
    if flags & 0x80 != 0 {
        let bytes = r.rest("Name (unverified)", "");
        let name = String::from_utf8_lossy(bytes)
            .trim_end_matches('\0')
            .to_string();
        r.value(format!("{name} (UTF-8 · unverified)"));
        d.field("Name (unverified)", &name);
        d.summary = format!(
            "{name} · {} · {} path entries",
            d.route.unwrap().name(),
            d.hops.unwrap()
        );
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
    fn assert_structure(fields: &[WireField], range: Range<usize>) {
        let mut end = range.start;
        for field in fields {
            assert_eq!(field.range.start, end, "out of order: {}", field.name);
            assert!(field.range.end >= field.range.start && field.range.end <= range.end);
            assert!(field.bits.is_none());
            end = field.range.end;
            if field
                .children
                .first()
                .is_some_and(|child| child.bits.is_some())
            {
                let mut bit_end = 0;
                assert_eq!(field.range.len(), 1);
                for child in &field.children {
                    assert_eq!(child.range, field.range);
                    let bits = child.bits.as_ref().unwrap();
                    assert_eq!(bits.start, bit_end);
                    assert!(bits.start < bits.end && bits.end <= 8);
                    bit_end = bits.end;
                }
                assert_eq!(bit_end, 8);
            } else if !field.children.is_empty() {
                assert_structure(&field.children, field.range.clone());
            }
        }
        assert_eq!(end, range.end, "unaccounted bytes");
    }
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
    fn payload_envelopes_follow_wire_order_and_keep_ciphertext_opaque() {
        for (ty, length, names) in [
            (
                0,
                19,
                vec!["Destination hash", "Source hash", "MAC", "Ciphertext"],
            ),
            (
                1,
                19,
                vec!["Destination hash", "Source hash", "MAC", "Ciphertext"],
            ),
            (
                2,
                19,
                vec!["Destination hash", "Source hash", "MAC", "Ciphertext"],
            ),
            (
                8,
                19,
                vec!["Destination hash", "Source hash", "MAC", "Ciphertext"],
            ),
            (5, 19, vec!["Channel hash", "MAC", "Ciphertext"]),
            (6, 19, vec!["Channel hash", "MAC", "Ciphertext"]),
            (
                7,
                36,
                vec!["Destination hash", "Sender public key", "MAC", "Ciphertext"],
            ),
            (9, 10, vec!["Trace tag", "Auth code", "Flags", "Trace data"]),
            (15, 19, vec!["Body"]),
        ] {
            let mut frame = vec![0x88, 0, 150, ty << 2 | 1, 0];
            frame.extend((0..length).map(|i| i as u8));
            let d = decode(&frame);
            assert!(d.warning.is_none(), "{:?}", d.warning);
            assert_structure(&d.structure, 0..frame.len());
            let payload = d.structure.last().unwrap();
            assert_eq!(payload.name, "Payload");
            assert_eq!(payload.range, 5..frame.len());
            assert_eq!(
                payload
                    .children
                    .iter()
                    .map(|field| field.name.as_str())
                    .collect::<Vec<_>>(),
                names
            );
            if let Some(ciphertext) = payload
                .children
                .iter()
                .find(|field| field.name == "Ciphertext")
            {
                assert!(ciphertext.children.is_empty());
                assert!(ciphertext.interpretation.starts_with("Encrypted"));
                assert_eq!(ciphertext.range.end, frame.len());
            }
        }
        let d = decode(&[0x88, 0, 150, 0x15, 0, 0xab, 0xcd]);
        let partial_mac = &d.structure.last().unwrap().children[1];
        assert_eq!(partial_mac.range, 6..7);
        assert!(partial_mac.interpretation.contains("expected 2 B, got 1 B"));
    }
    #[test]
    fn advert_tree_preserves_optional_fields_and_every_truncation() {
        let mut frame = vec![0x88, 0, 150, 0x11, 0];
        frame.extend(0..32);
        frame.extend_from_slice(&1_793_544_000u32.to_le_bytes());
        frame.extend(0x80..0xc0);
        frame.push(0xf2);
        frame.extend_from_slice(&51_507_351i32.to_le_bytes());
        frame.extend_from_slice(&(-127_758i32).to_le_bytes());
        frame.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        frame.extend_from_slice("Rélais 東京".as_bytes());
        let d = decode(&frame);
        assert!(d.warning.is_none());
        let fields = &d.structure.last().unwrap().children;
        assert_eq!(
            fields
                .iter()
                .map(|f| (f.name.as_str(), f.range.clone()))
                .collect::<Vec<_>>(),
            vec![
                ("Public key", 5..37),
                ("Advert timestamp", 37..41),
                ("Signature", 41..105),
                ("Application data", 105..frame.len()),
            ]
        );
        let app = &fields[3].children;
        assert_eq!(
            app.iter()
                .map(|f| (f.name.as_str(), f.range.clone()))
                .collect::<Vec<_>>(),
            vec![
                ("Flags", 105..106),
                ("Latitude", 106..110),
                ("Longitude", 110..114),
                ("Feature 1", 114..116),
                ("Feature 2", 116..118),
                ("Name (unverified)", 118..frame.len()),
            ]
        );
        assert!(app[1].interpretation.starts_with("51.507351°"));
        assert!(app[2].interpretation.starts_with("-0.127758°"));
        assert!(app[3].interpretation.contains("Reserved"));
        for length in 0..=frame.len() {
            let decoded = decode(&frame[..length]);
            assert_structure(&decoded.structure, 0..length);
        }
    }
    #[test]
    fn arbitrary_short_inputs_never_panic() {
        for len in 0..260 {
            for byte in 0..=255 {
                let decoded = decode(&vec![byte; len]);
                assert_structure(&decoded.structure, 0..len);
            }
        }
        for n in 0..50 {
            let f = sample_frame(n);
            for len in 0..=f.len() {
                let decoded = decode(&f[..len]);
                assert_structure(&decoded.structure, 0..len);
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
                assert_structure(&d.structure, 0..frame.len());
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
