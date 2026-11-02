//! Unencrypted trace, discovery/control, and multipart ACK payloads.
use super::{Decoded, WireField, WireReader, hex};

pub(super) fn role(value: u8) -> &'static str {
    match value {
        1 => "Chat node",
        2 => "Repeater",
        3 => "Room server",
        4 => "Sensor",
        _ => "Unknown",
    }
}

fn uint32(r: &mut WireReader<'_>, d: &mut Decoded, name: &str) -> Result<u32, &'static str> {
    let bytes = r.read(name, 4)?;
    let value = u32::from_le_bytes(bytes.try_into().unwrap());
    let interpretation = format!("0x{value:08X} · {value} (u32 LE)");
    r.value(&interpretation);
    d.field(name, interpretation);
    Ok(value)
}

pub(super) fn trace(r: &mut WireReader<'_>, d: &mut Decoded) -> Result<(), &'static str> {
    uint32(r, d, "Trace tag").map_err(|_| "Truncated trace tag")?;
    uint32(r, d, "Auth code").map_err(|_| "Truncated trace authentication code")?;
    r.value(format!(
        "{} · not verified",
        r.fields.last().unwrap().interpretation
    ));
    let flags = r.read("Flags", 1).map_err(|_| "Missing trace flags")?[0];
    let width = 1usize << (flags & 3);
    let offset = r.fields.last().unwrap().range.start;
    r.fields.last_mut().unwrap().children = vec![
        WireField::bit(
            "Target hash width",
            offset,
            0..2,
            format!("{width} B (1 << selector)"),
        ),
        WireField::bit("Other flags", offset, 2..8, "Application-defined"),
    ];
    d.field(
        "Flags",
        format!("0x{flags:02X} · {width}-byte trace target hashes"),
    );
    let bytes = r.rest("Trace targets", "");
    let start = r.fields.last().unwrap().range.start;
    r.value(format!(
        "{} targets × {width} B · supplied route",
        bytes.len() / width
    ));
    let mut targets = WireReader::new(bytes, start);
    let mut index = 1;
    while targets.remaining() > 0 {
        if targets.read(&format!("Target {index}"), width).is_err() {
            d.warn(format!(
                "Incomplete trace target: {} path bytes do not align to {width}-byte hashes",
                bytes.len()
            ));
            break;
        }
        index += 1;
    }
    r.fields.last_mut().unwrap().children = targets.fields;
    d.field(
        "Trace targets",
        bytes.chunks(width).map(hex).collect::<Vec<_>>().join(" → "),
    );
    Ok(())
}

pub(super) fn control(r: &mut WireReader<'_>, d: &mut Decoded) -> Result<(), &'static str> {
    let flags = r
        .read("Control flags", 1)
        .map_err(|_| "Missing control flags")?[0];
    let offset = r.fields.last().unwrap().range.start;
    let subtype = flags >> 4;
    let children = match subtype {
        8 => vec![
            WireField::bit(
                "Prefix only",
                offset,
                0..1,
                if flags & 1 != 0 { "yes" } else { "no" },
            ),
            WireField::bit("Reserved flags", offset, 1..4, "Reserved"),
        ],
        9 => vec![WireField::bit("Node role", offset, 0..4, role(flags & 15))],
        _ => vec![WireField::bit(
            "Other flags",
            offset,
            0..4,
            "Not interpreted",
        )],
    };
    let name = match subtype {
        8 => "Discovery request",
        9 => "Discovery response",
        _ => "Unsupported control subtype",
    };
    r.value(name);
    r.fields.last_mut().unwrap().children = children;
    r.fields.last_mut().unwrap().children.push(WireField::bit(
        "Control subtype",
        offset,
        4..8,
        name,
    ));
    d.field("Control subtype", format!("0x{subtype:X} · {name}"));
    match subtype {
        8 => {
            let filter = r
                .read("Role filter", 1)
                .map_err(|_| "Missing discovery role filter")?[0];
            let offset = r.fields.last().unwrap().range.start;
            r.fields.last_mut().unwrap().children = (0..8)
                .map(|bit| {
                    let label = match bit {
                        0 => "Unknown role",
                        1..=4 => role(bit),
                        _ => "Reserved role",
                    };
                    WireField::bit(
                        &format!("{label} ({bit})"),
                        offset,
                        bit..bit + 1,
                        if filter & (1 << bit) != 0 {
                            "included"
                        } else {
                            "excluded"
                        },
                    )
                })
                .collect();
            d.field("Role filter", format!("0x{filter:02X}"));
            uint32(r, d, "Discovery tag").map_err(|_| "Truncated discovery tag")?;
            if r.remaining() > 0 {
                let since =
                    uint32(r, d, "Since").map_err(|_| "Truncated discovery since timestamp")?;
                let date = chrono::DateTime::from_timestamp(since.into(), 0).unwrap();
                r.value(format!(
                    "{since} (u32 LE) · {}",
                    date.format("%Y-%m-%d %H:%M:%S UTC")
                ));
            }
        }
        9 => {
            d.field("Node role", role(flags & 15));
            let snr = r
                .read("Reported request SNR", 1)
                .map_err(|_| "Missing discovery reported SNR")?[0] as i8;
            let description = format!(
                "{:+.2} dB (i8 / 4) · request reception at responding node",
                snr as f32 / 4.0
            );
            r.value(&description);
            d.field("Reported request SNR", description);
            uint32(r, d, "Discovery tag").map_err(|_| "Truncated discovery tag")?;
            let size = r.remaining();
            if size == 8 || size == 32 {
                let name = if size == 8 {
                    "Public key prefix"
                } else {
                    "Public key"
                };
                let bytes = r.read(name, size).unwrap();
                d.field(name, hex(bytes));
                r.value("Advertised Ed25519 identity · unverified");
            } else {
                r.rest("Discovery key bytes", "Unexpected length · not interpreted");
                d.warn(format!(
                    "Invalid discovery public key length: got {size} bytes; expected 8 or 32 bytes"
                ));
            }
        }
        _ => {
            r.rest("Body", "Unsupported control subtype · not interpreted");
        }
    }
    if r.remaining() > 0 {
        r.rest("Trailing bytes", "Not interpreted · extra control bytes");
        d.warn("Unexpected trailing control bytes");
    }
    Ok(())
}

pub(super) fn multipart(r: &mut WireReader<'_>, d: &mut Decoded) -> Result<(), &'static str> {
    let flags = r
        .read("Multipart flags", 1)
        .map_err(|_| "Missing multipart flags")?[0];
    let offset = r.fields.last().unwrap().range.start;
    let ty = flags & 15;
    let remaining = flags >> 4;
    r.fields.last_mut().unwrap().children = vec![
        WireField::bit(
            "Inner payload type",
            offset,
            0..4,
            if ty == 3 { "ACK" } else { "Unsupported" },
        ),
        WireField::bit("Packets remaining", offset, 4..8, remaining),
    ];
    d.field("Packets remaining", remaining);
    if ty == 3 {
        let size = r.remaining();
        uint32(r, d, "Acknowledgment")
            .map_err(|_| "Truncated multipart ACK (expected four bytes)")?;
        if size != 4 {
            r.rest(
                "Trailing bytes",
                "Not interpreted · extra multipart ACK bytes",
            );
            d.warn(format!(
                "Multipart ACK must contain exactly four bytes; got {size}"
            ));
        }
    } else {
        r.rest("Body", "Unsupported multipart inner type · not interpreted");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{decode, tests::assert_structure};
    use super::*;

    fn frame(ty: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x88, 0xf8, 0xa0, (ty << 2) | 2, 0];
        frame.extend_from_slice(payload);
        frame
    }

    fn fields(decoded: &Decoded) -> &[WireField] {
        &decoded.structure.last().unwrap().children
    }

    fn every_truncation(frame: &[u8]) {
        let original = frame.to_vec();
        for length in 0..=frame.len() {
            let decoded = decode(&frame[..length]);
            assert_structure(&decoded.structure, 0..length);
        }
        assert_eq!(frame, original);
    }

    #[test]
    fn discovery_requests_decode_flags_filters_unsigned_tags_and_optional_since() {
        for prefix in [0, 1] {
            for since in [None, Some(0), Some(0x8000_0000u32), Some(u32::MAX)] {
                let mut payload = vec![0x80 | prefix, 0x1e];
                payload.extend_from_slice(&u32::MAX.to_le_bytes());
                if let Some(since) = since {
                    payload.extend_from_slice(&since.to_le_bytes());
                }
                let frame = frame(11, &payload);
                let decoded = decode(&frame);
                assert!(decoded.warning.is_none(), "{:?}", decoded.warning);
                assert_eq!(
                    fields(&decoded)[0].children[0].interpretation,
                    if prefix == 1 { "yes" } else { "no" }
                );
                let filter = &fields(&decoded)[1];
                assert_eq!(filter.children.len(), 8);
                for bit in 1..=4 {
                    assert_eq!(filter.children[bit].interpretation, "included");
                }
                assert!(
                    fields(&decoded)[2]
                        .interpretation
                        .contains("4294967295 (u32 LE)")
                );
                if let Some(since) = since {
                    assert!(
                        fields(&decoded)[3]
                            .interpretation
                            .starts_with(&format!("{since} (u32 LE)"))
                    );
                } else {
                    assert_eq!(fields(&decoded).len(), 3);
                }
                every_truncation(&frame);
            }
        }
        let mut payload = vec![0x80, 0, 1, 2, 3, 4];
        for partial in 1..4 {
            payload.resize(6 + partial, 0);
            let decoded = decode(&frame(11, &payload));
            assert!(
                decoded
                    .warning
                    .unwrap()
                    .contains("Truncated discovery since")
            );
        }
        payload.resize(11, 0);
        let decoded = decode(&frame(11, &payload));
        assert_eq!(fields(&decoded).last().unwrap().name, "Trailing bytes");
        assert!(decoded.warning.unwrap().contains("trailing control bytes"));
    }

    #[test]
    fn discovery_responses_distinguish_reported_snr_and_validate_key_lengths() {
        for role_value in [0, 1, 2, 3, 4, 15] {
            for size in [8, 32] {
                let mut payload = vec![0x90 | role_value, 0xdc];
                payload.extend_from_slice(&u32::MAX.to_le_bytes());
                payload.extend(0..size);
                let frame = frame(11, &payload);
                let decoded = decode(&frame);
                assert!(decoded.warning.is_none());
                assert_eq!(decoded.snr, Some(-2.0));
                assert!(fields(&decoded)[1].interpretation.starts_with("-9.00 dB"));
                assert!(fields(&decoded)[2].interpretation.contains("4294967295"));
                assert_eq!(fields(&decoded)[3].range, 11..11 + size as usize);
                assert_eq!(
                    fields(&decoded)[3].name,
                    if size == 8 {
                        "Public key prefix"
                    } else {
                        "Public key"
                    }
                );
                assert_eq!(
                    fields(&decoded)[0].children[0].interpretation,
                    role(role_value)
                );
                every_truncation(&frame);
            }
        }
        for size in 0..40 {
            if size == 8 || size == 32 {
                continue;
            }
            let mut payload = vec![0x92, 0, 1, 2, 3, 4];
            payload.extend(vec![0x42; size]);
            let frame = frame(11, &payload);
            let decoded = decode(&frame);
            assert!(
                decoded
                    .warning
                    .as_ref()
                    .unwrap()
                    .contains(&format!("got {size} bytes"))
            );
            assert_eq!(fields(&decoded).last().unwrap().range.len(), size);
            assert_structure(&decoded.structure, 0..frame.len());
        }
        let frame = frame(11, &[0x32, 0xde, 0xad, 0xbe, 0xef]);
        let decoded = decode(&frame);
        assert!(decoded.warning.is_none());
        assert_eq!(
            &frame[fields(&decoded)[1].range.clone()],
            &[0xde, 0xad, 0xbe, 0xef]
        );
        assert!(
            fields(&decoded)[1]
                .interpretation
                .contains("Unsupported control subtype")
        );
        every_truncation(&frame);
    }

    #[test]
    fn traces_separate_collected_snr_from_targets_of_all_four_widths() {
        for selector in 0..4 {
            let width = 1 << selector;
            let mut payload = Vec::from(0xfedc_ba98u32.to_le_bytes());
            payload.extend_from_slice(&u32::MAX.to_le_bytes());
            payload.push(0xa0 | selector);
            payload.extend(0..(2 * width) as u8);
            let mut frame = frame(9, &payload);
            frame[4] = 2;
            frame.splice(5..5, [0x30, 0xf8]); // outer path = +12 dB, -2 dB
            let decoded = decode(&frame);
            assert!(decoded.warning.is_none(), "{:?}", decoded.warning);
            assert!(fields(&decoded)[0].interpretation.contains("4275878552"));
            assert!(fields(&decoded)[1].interpretation.contains("4294967295"));
            assert!(
                fields(&decoded)[2].children[0]
                    .interpretation
                    .contains(&format!("{width} B"))
            );
            let targets = &fields(&decoded)[3];
            assert_eq!(targets.children.len(), 2);
            assert_eq!(targets.children[0].range.len(), width);
            assert_eq!(targets.children[1].range.len(), width);
            assert_eq!(decoded.hops, Some(2));
            assert!(
                decoded
                    .fields
                    .iter()
                    .any(|(k, v)| k == "Trace SNR samples" && v == "+12.00 → -2.00")
            );
            every_truncation(&frame);
            if width > 1 {
                frame.pop();
                let decoded = decode(&frame);
                assert!(
                    decoded
                        .warning
                        .as_ref()
                        .unwrap()
                        .contains("Incomplete trace target")
                );
                assert_eq!(fields(&decoded)[3].children[1].range.len(), width - 1);
                assert!(
                    fields(&decoded)[3].children[1]
                        .interpretation
                        .starts_with("Truncated")
                );
                assert_structure(&decoded.structure, 0..frame.len());
            }
        }
        let decoded = decode(&frame(9, &[0; 9]));
        assert!(decoded.warning.is_none());
        assert!(fields(&decoded)[3].range.is_empty());
    }

    #[test]
    fn multipart_acks_decode_remaining_count_and_preserve_unsupported_and_extra_data() {
        for remaining in [0, 1, 15] {
            let mut payload = vec![(remaining << 4) | 3];
            payload.extend_from_slice(&0xfedc_ba98u32.to_le_bytes());
            let frame = frame(10, &payload);
            let decoded = decode(&frame);
            assert!(decoded.warning.is_none());
            assert_eq!(
                fields(&decoded)[0].children[1].interpretation,
                remaining.to_string()
            );
            assert!(fields(&decoded)[1].interpretation.contains("0xFEDCBA98"));
            every_truncation(&frame);
            let mut extra = frame.clone();
            extra.extend_from_slice(&[0xde, 0xad]);
            let decoded = decode(&extra);
            assert!(decoded.warning.as_ref().unwrap().contains("got 6"));
            assert_eq!(&extra[fields(&decoded)[2].range.clone()], &[0xde, 0xad]);
            every_truncation(&extra);
        }
        let frame = frame(10, &[0x12, 0xde, 0xad]);
        let decoded = decode(&frame);
        assert!(decoded.warning.is_none());
        assert_eq!(&frame[fields(&decoded)[1].range.clone()], &[0xde, 0xad]);
        assert!(
            fields(&decoded)[1]
                .interpretation
                .contains("Unsupported multipart")
        );
        every_truncation(&frame);
    }
}
