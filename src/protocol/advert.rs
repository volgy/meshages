//! Advert envelopes, strict Ed25519 verification, and optional application fields.
use super::{Decoded, WireField, WireReader, hex, payloads::role};
use ed25519_dalek::{Signature, VerifyingKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdvertSignature {
    Valid,
    Invalid,
    Unverified(&'static str),
}

impl AdvertSignature {
    pub fn description(&self) -> String {
        match self {
            Self::Valid => "Valid Ed25519 signature · contents signed by advertised key; identity not established".into(),
            Self::Invalid => "Invalid Ed25519 signature · contents unverified".into(),
            Self::Unverified(reason) => format!("Signature unverified · {reason}"),
        }
    }

    fn content_note(&self) -> &'static str {
        if matches!(self, Self::Valid) {
            "signed by advertised key"
        } else {
            "unverified"
        }
    }
}

pub(super) fn decode(r: &mut WireReader<'_>, d: &mut Decoded) -> Result<(), &'static str> {
    let key = r
        .read("Public key", 32)
        .map_err(|_| "Truncated advertisement (key, timestamp, signature)")?;
    d.field("Public key", hex(key));
    r.value("Ed25519 · advertised identity not established");
    let timestamp_bytes = r
        .read("Advert timestamp", 4)
        .map_err(|_| "Truncated advertisement (key, timestamp, signature)")?;
    let timestamp = u32::from_le_bytes(timestamp_bytes.try_into().unwrap());
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
    let signature_index = r.fields.len() - 1;
    let app_data = r.rest("Application data", "");
    d.field("Application data", hex(app_data));

    // Sign the original timestamp and app bytes, before any text decoding or NUL handling.
    let status = if app_data.len() > 32 {
        d.warn("Advert application data exceeds the 32-byte firmware maximum");
        AdvertSignature::Unverified("Application data exceeds 32 bytes")
    } else {
        let mut message = Vec::with_capacity(36 + app_data.len());
        message.extend_from_slice(key);
        message.extend_from_slice(timestamp_bytes);
        message.extend_from_slice(app_data);
        let valid = VerifyingKey::from_bytes(key.try_into().unwrap())
            .and_then(|key| {
                key.verify_strict(
                    &message,
                    &Signature::from_bytes(signature.try_into().unwrap()),
                )
            })
            .is_ok();
        if valid {
            AdvertSignature::Valid
        } else {
            d.warn("Invalid advert Ed25519 signature");
            AdvertSignature::Invalid
        }
    };
    r.fields[signature_index].interpretation = status.description();
    d.field("Verification", status.description());
    let note = status.content_note();
    d.advert_signature = Some(status);
    r.value(note);
    let mut app = WireReader::new(app_data, r.fields.last().unwrap().range.start);
    let result = application(&mut app, d, note);
    app.preserve_remainder();
    r.fields.last_mut().unwrap().children = app.fields;
    result
}

fn application(r: &mut WireReader<'_>, d: &mut Decoded, note: &str) -> Result<(), &'static str> {
    if r.remaining() == 0 {
        return Ok(());
    }
    let flags = r.read("Flags", 1)?[0];
    let offset = r.fields.last().unwrap().range.start;
    let node_role = role(flags & 15);
    d.field("Node role", node_role);
    r.fields.last_mut().unwrap().children =
        vec![WireField::bit("Node role", offset, 0..4, node_role)];
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
        let mut coordinates = [0.0; 2];
        for (index, name) in ["Latitude", "Longitude"].into_iter().enumerate() {
            let bytes = r
                .read(name, 4)
                .map_err(|_| "Truncated advert coordinates")?;
            let raw = i32::from_le_bytes(bytes.try_into().unwrap());
            coordinates[index] = raw as f64 / 1e6;
            r.value(format!(
                "{:.6}° · {raw} (i32 LE / 10⁶) · {note}",
                coordinates[index]
            ));
        }
        d.field(
            "Location",
            format!("{:.6}, {:.6} · {note}", coordinates[0], coordinates[1]),
        );
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
        let length = r.bytes[r.pos..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(r.remaining());
        let bytes = r.read("Name", length).unwrap();
        let name = String::from_utf8_lossy(bytes);
        r.value(format!("{name} (UTF-8 · {note})"));
        d.field("Name", &name);
        if std::str::from_utf8(bytes).is_err() {
            d.warn("Advert name contains invalid UTF-8; original bytes preserved");
        }
        d.summary = format!(
            "{name} · {} · {} path entries",
            d.route.unwrap().name(),
            d.hops.unwrap()
        );
        if r.remaining() > 0 {
            r.read("Name terminator", 1).unwrap();
            r.value("NUL");
            if r.remaining() > 0 {
                if r.bytes[r.pos..].iter().all(|&b| b == 0) {
                    r.rest("Padding", "Zero bytes after name terminator");
                } else {
                    r.rest(
                        "Trailing bytes",
                        "Not interpreted · nonzero bytes after name terminator",
                    );
                    d.warn("Nonzero bytes after the advert name NUL terminator");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_vectors {
    #[derive(serde::Deserialize)]
    pub struct Vector {
        pub name: String,
        pub packet: String,
        pub status: String,
        pub warning: bool,
    }

    pub fn all() -> Vec<Vector> {
        let data: serde_json::Value =
            serde_json::from_str(include_str!("advert_vectors.json")).unwrap();
        serde_json::from_value(data["vectors"].clone()).unwrap()
    }

    pub fn frame(name: &str) -> Vec<u8> {
        let vector = all().into_iter().find(|v| v.name == name).unwrap();
        let mut frame = vec![0x88, 0xf8, 0xa0];
        frame.extend(super::super::channel::test_vectors::bytes(&vector.packet));
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::super::{decode, tests::assert_structure};
    use super::*;

    #[test]
    fn independent_signatures_cover_empty_optional_and_malformed_application_data() {
        for vector in test_vectors::all() {
            let frame = test_vectors::frame(&vector.name);
            let original = frame.clone();
            let decoded = decode(&frame);
            let expected = if vector.status == "valid" {
                AdvertSignature::Valid
            } else {
                AdvertSignature::Unverified("Application data exceeds 32 bytes")
            };
            assert_eq!(decoded.advert_signature, Some(expected), "{}", vector.name);
            assert_eq!(
                decoded.warning.is_some(),
                vector.warning,
                "{}: {:?}",
                vector.name,
                decoded.warning
            );
            assert_structure(&decoded.structure, 0..frame.len());
            assert_eq!(frame, original);
            if vector.name == "optional_fields" {
                assert!(
                    decoded
                        .fields
                        .iter()
                        .any(|(k, v)| k == "Node role" && v == "Chat node")
                );
                assert!(
                    decoded
                        .fields
                        .iter()
                        .any(|(k, v)| k == "Advert timestamp" && v == "4275878552")
                );
                assert!(
                    decoded
                        .fields
                        .iter()
                        .any(|(k, v)| k == "Name" && v == "Rélais 東京")
                );
            }
        }
    }

    #[test]
    fn altered_key_timestamp_signature_and_application_bytes_fail_verification() {
        for name in [
            "public_cougar",
            "optional_fields",
            "empty_application",
            "embedded_nul",
        ] {
            let original = test_vectors::frame(name);
            let mut offsets = vec![5, 37, 41];
            if original.len() > 105 {
                offsets.push(original.len() - 1);
            }
            for offset in offsets {
                let mut frame = original.clone();
                frame[offset] ^= 1;
                let decoded = decode(&frame);
                assert_eq!(
                    decoded.advert_signature,
                    Some(AdvertSignature::Invalid),
                    "{name} offset {offset}"
                );
                assert!(
                    decoded
                        .warning
                        .as_ref()
                        .unwrap()
                        .contains("Invalid advert Ed25519 signature")
                );
                assert_structure(&decoded.structure, 0..frame.len());
            }
        }
        // The signature cannot be used to make a low-order advertised key appear valid.
        let mut weak = test_vectors::frame("empty_application");
        weak[5..37].fill(0);
        weak[5] = 1; // identity point
        weak[41..105].fill(0);
        weak[41] = 1; // R = identity, S = 0
        assert_eq!(
            decode(&weak).advert_signature,
            Some(AdvertSignature::Invalid)
        );
    }

    #[test]
    fn names_keep_terminators_padding_trailing_bytes_and_utf8_errors() {
        let frame = test_vectors::frame("embedded_nul");
        let decoded = decode(&frame);
        let app = &decoded.structure.last().unwrap().children[3].children;
        let name = app.iter().find(|f| f.name == "Name").unwrap();
        assert_eq!(name.range, 106..111);
        assert!(name.interpretation.starts_with("Alice (UTF-8"));
        assert!(
            decoded
                .fields
                .iter()
                .any(|(k, v)| k == "Name" && v == "Alice")
        );
        assert!(!decoded.summary.contains("tail"));
        let terminator = app.iter().find(|f| f.name == "Name terminator").unwrap();
        assert_eq!(terminator.range, 111..112);
        assert_eq!(frame[terminator.range.clone()], [0]);
        let trailing = app.iter().find(|f| f.name == "Trailing bytes").unwrap();
        assert_eq!(&frame[trailing.range.clone()], b"tail");
        assert!(decoded.warning.unwrap().contains("Nonzero bytes"));

        let mut padded = frame.clone();
        padded[112..].fill(0);
        let decoded = decode(&padded);
        assert!(
            decoded.structure.last().unwrap().children[3]
                .children
                .iter()
                .any(|f| f.name == "Padding")
        );
        assert!(!decoded.warning.unwrap().contains("Nonzero bytes"));
        assert_structure(&decoded.structure, 0..padded.len());

        let mut invalid = test_vectors::frame("invalid_utf8");
        invalid[41] ^= 1;
        let decoded = decode(&invalid);
        let warning = decoded.warning.unwrap();
        assert!(
            warning.contains("invalid UTF-8")
                && warning.contains("Invalid advert Ed25519 signature")
        );
        assert_structure(&decoded.structure, 0..invalid.len());
    }

    #[test]
    fn every_truncation_preserves_bytes_and_incomplete_or_unsupported_adverts_are_unverified() {
        for vector in test_vectors::all() {
            let frame = test_vectors::frame(&vector.name);
            for length in 0..=frame.len() {
                let decoded = decode(&frame[..length]);
                assert_structure(&decoded.structure, 0..length);
                if length <= 3 {
                    assert_eq!(decoded.advert_signature, None);
                } else if length < 105 {
                    assert_eq!(
                        decoded.advert_signature,
                        Some(AdvertSignature::Unverified("Incomplete advert envelope"))
                    );
                }
            }
        }
        let mut unsupported = test_vectors::frame("public_cougar");
        unsupported[3] |= 0x40;
        let decoded = decode(&unsupported);
        assert_eq!(
            decoded.advert_signature,
            Some(AdvertSignature::Unverified("Unsupported payload version"))
        );
        assert_structure(&decoded.structure, 0..unsupported.len());
        assert!(decoded.structure.last().unwrap().children.is_empty());
        assert_eq!(
            decode(&[0x88, 0, 0, 0x0d, 0, 1, 2, 3, 4]).advert_signature,
            None
        );
    }
}
