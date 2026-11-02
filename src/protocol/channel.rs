//! MeshCore channel crypto and plaintext envelopes.
//! Reference: MeshCore src/Utils.cpp and src/helpers/BaseChatMesh.cpp.
use super::{Decoded, WireField, WireReader};
use aes::{
    Aes128,
    cipher::{Block, BlockDecrypt, KeyInit},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{collections::BTreeMap, ops::Range};

#[derive(Clone, Debug)]
pub struct ChannelEnvelope {
    pub payload_type: u8,
    mac: [u8; 2],
    ciphertext: Vec<u8>,
    /// Absolute wire range; plaintext uses a separate buffer and offsets.
    pub range: Range<usize>,
    pub status: ChannelStatus,
}

#[derive(Clone, Debug)]
pub enum ChannelStatus {
    NoKey,
    MacMismatch,
    Invalid(String),
    Ambiguous(Vec<Vec<String>>),
    Decrypted(Plaintext),
}

#[derive(Clone, Debug)]
pub struct Plaintext {
    pub channels: Vec<String>,
    /// Includes all zero padding. Never substituted into the captured wire bytes.
    pub bytes: Vec<u8>,
    pub fields: Vec<WireField>,
    pub warning: Option<String>,
}

impl ChannelStatus {
    pub fn description(&self) -> String {
        match self {
            Self::NoKey => "Encrypted · no matching channel key in catalogue".into(),
            Self::MacMismatch => "Encrypted · no candidate key passed the 16-bit MAC check".into(),
            Self::Invalid(reason) => format!("Encrypted · malformed ciphertext: {reason}"),
            Self::Ambiguous(groups) => format!(
                "Encrypted · ambiguous MAC matches: {}",
                groups
                    .iter()
                    .map(|names| names.join(" / "))
                    .collect::<Vec<_>>()
                    .join(" | ")
            ),
            Self::Decrypted(plain) => format!(
                "Decrypted · {} · 16-bit MAC matched",
                plain.channels.join(" / ")
            ),
        }
    }
    pub fn mac_description(&self) -> String {
        match self {
            Self::NoKey => "Cipher MAC · not checked (no matching key)".into(),
            Self::MacMismatch => "Cipher MAC · no candidate key matched".into(),
            Self::Invalid(_) => "Cipher MAC · not checked (malformed ciphertext)".into(),
            Self::Ambiguous(_) => "16-bit MAC matched multiple distinct keys · ambiguous".into(),
            Self::Decrypted(_) => "16-bit MAC matched".into(),
        }
    }
}

impl ChannelEnvelope {
    pub(super) fn new(
        payload_type: u8,
        mac: [u8; 2],
        ciphertext: Vec<u8>,
        range: Range<usize>,
    ) -> Self {
        Self {
            payload_type,
            mac,
            ciphertext,
            range,
            status: ChannelStatus::NoKey,
        }
    }

    /// Candidates have already been filtered by the channel's on-wire hash.
    pub fn decrypt(&mut self, candidates: impl IntoIterator<Item = (String, [u8; 16])>) {
        if self.ciphertext.is_empty() || !self.ciphertext.len().is_multiple_of(16) {
            self.status = ChannelStatus::Invalid("expected a nonempty multiple of 16 bytes".into());
            return;
        }
        let mut unique: BTreeMap<[u8; 16], Vec<String>> = BTreeMap::new();
        for (name, key) in candidates {
            let names = unique.entry(key).or_default();
            if !names.contains(&name) {
                names.push(name);
            }
        }
        if unique.is_empty() {
            self.status = ChannelStatus::NoKey;
            return;
        }
        let matches: Vec<_> = unique
            .into_iter()
            .filter(|(key, _)| {
                // Firmware uses a 32-byte secret with a zero-filled tail for 128-bit channels.
                let mut secret = [0u8; 32];
                secret[..16].copy_from_slice(key);
                let mut mac =
                    <Hmac<Sha256> as Mac>::new_from_slice(&secret).expect("HMAC key length");
                mac.update(&self.ciphertext);
                mac.verify_truncated_left(&self.mac).is_ok()
            })
            .collect();
        if matches.len() != 1 {
            self.status = if matches.is_empty() {
                ChannelStatus::MacMismatch
            } else {
                ChannelStatus::Ambiguous(matches.into_iter().map(|(_, names)| names).collect())
            };
            return;
        }
        let (key, channels) = matches.into_iter().next().unwrap();
        let cipher = Aes128::new_from_slice(&key).expect("128-bit channel key");
        let mut bytes = self.ciphertext.clone();
        for chunk in bytes.as_chunks_mut::<16>().0 {
            let mut block = Block::<Aes128>::default();
            block.copy_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
        self.status = ChannelStatus::Decrypted(parse_plaintext(self.payload_type, bytes, channels));
    }
}

fn parse_plaintext(payload_type: u8, bytes: Vec<u8>, channels: Vec<String>) -> Plaintext {
    let mut reader = WireReader::new(&bytes, 0);
    let result = match payload_type {
        5 => text(&mut reader),
        6 => datagram(&mut reader),
        _ => Err("Unsupported decrypted channel payload type"),
    };
    reader.preserve_remainder();
    let fields = reader.fields;
    Plaintext {
        channels,
        bytes,
        fields,
        warning: result.err().map(str::to_owned),
    }
}

fn text(r: &mut WireReader<'_>) -> Result<(), &'static str> {
    let bytes = r
        .read("Message timestamp", 4)
        .map_err(|_| "Truncated message timestamp")?;
    let timestamp = u32::from_le_bytes(bytes.try_into().unwrap());
    let date = chrono::DateTime::from_timestamp(timestamp.into(), 0).unwrap();
    r.value(format!(
        "{} · {timestamp} (u32 LE)",
        date.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    let flags = r.read("Text flags", 1).map_err(|_| "Missing text flags")?[0];
    let offset = r.fields.last().unwrap().range.start;
    let subtype = flags >> 2;
    r.fields.last_mut().unwrap().children = vec![
        WireField::bit("Attempt", offset, 0..2, flags & 3),
        WireField::bit(
            "Text type",
            offset,
            2..8,
            if subtype == 0 {
                "Plain text".into()
            } else {
                format!("0x{subtype:02X} · unsupported for channel text")
            },
        ),
    ];
    if subtype != 0 {
        r.rest("Body", "Unsupported channel text type · not interpreted");
        return Err("Unsupported channel text type; plaintext bytes preserved");
    }
    let start = r.pos;
    let size = r.bytes[start..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(r.remaining());
    let message = r.read("Message", size).unwrap();
    let valid_utf8 = std::str::from_utf8(message).is_ok();
    r.value(String::from_utf8_lossy(message));
    if valid_utf8 && let Some(separator) = message.windows(2).position(|pair| pair == b": ") {
        r.value("UTF-8");
        r.fields.last_mut().unwrap().children = vec![
            WireField::new(
                "Sender name (unverified)",
                start..start + separator,
                String::from_utf8_lossy(&message[..separator]),
            ),
            WireField::new(
                "Separator",
                start + separator..start + separator + 2,
                "\": \"",
            ),
            WireField::new(
                "Text",
                start + separator + 2..start + size,
                String::from_utf8_lossy(&message[separator + 2..]),
            ),
        ];
    }
    let padding = padding(
        r,
        "Nonzero bytes after the text NUL terminator",
        "NUL / zero padding",
    );
    if !valid_utf8 {
        return Err("Message contains invalid UTF-8; original plaintext bytes preserved");
    }
    padding
}

fn datagram(r: &mut WireReader<'_>) -> Result<(), &'static str> {
    let ty = r
        .read("Data type", 2)
        .map_err(|_| "Truncated datagram type")?;
    r.value(format!(
        "0x{:04X} (u16 LE)",
        u16::from_le_bytes(ty.try_into().unwrap())
    ));
    let length = r
        .read("Data length", 1)
        .map_err(|_| "Missing datagram length")?[0] as usize;
    r.value(format!("{length} B"));
    r.read("Data", length)
        .map_err(|_| "Datagram length exceeds available plaintext")?;
    r.value("Application-defined data · not interpreted");
    padding(
        r,
        "Nonzero bytes after the declared datagram data",
        "Zero padding",
    )
}

fn padding(
    r: &mut WireReader<'_>,
    error: &'static str,
    description: &str,
) -> Result<(), &'static str> {
    if r.remaining() == 0 {
        return Ok(());
    }
    if r.bytes[r.pos..].iter().all(|&b| b == 0) {
        r.rest("Padding", description);
        Ok(())
    } else {
        r.rest("Trailing bytes", "Not interpreted · nonzero trailing bytes");
        Err(error)
    }
}

/// Apply local keys without altering the wire tree's coordinate space or capture bytes.
pub fn apply_keys(decoded: &mut Decoded, candidates: impl IntoIterator<Item = (String, [u8; 16])>) {
    let Some(channel) = decoded.channel.as_mut() else {
        return;
    };
    channel.decrypt(candidates);
    let description = channel.status.description();
    let mac = channel.status.mac_description();
    let range = channel.range.clone();
    let warning = match &channel.status {
        ChannelStatus::Invalid(reason) => Some(format!("Invalid channel ciphertext: {reason}")),
        ChannelStatus::Ambiguous(_) => Some(
            "Multiple distinct channel keys passed the 16-bit MAC check; decryption is ambiguous"
                .into(),
        ),
        ChannelStatus::Decrypted(plain) => plain
            .warning
            .as_ref()
            .map(|warning| format!("Decrypted payload: {warning}")),
        _ => None,
    };
    if decoded.warning.is_none() {
        decoded.warning = warning;
    }
    if let Some((_, value)) = decoded
        .fields
        .iter_mut()
        .find(|(name, _)| name == "Content")
    {
        *value = description.clone();
    }
    fn update(fields: &mut [WireField], range: &Range<usize>, mac: &str, description: &str) {
        for field in fields {
            if field.name == "Ciphertext" && field.range == *range {
                field.interpretation = description.into();
            } else if field.name == "MAC" && field.range.end == range.start {
                field.interpretation = mac.into();
            }
            update(&mut field.children, range, mac, description);
        }
    }
    let wire_description = if matches!(channel.status, ChannelStatus::Decrypted(_)) {
        "Decrypted below"
    } else {
        &description
    };
    update(&mut decoded.structure, &range, &mac, wire_description);
}

#[cfg(test)]
pub(crate) mod test_vectors {
    #[derive(serde::Deserialize)]
    pub struct Vector {
        pub name: String,
        pub payload_type: u8,
        pub key: String,
        pub channel_hash: u8,
        pub mac: String,
        pub ciphertext: String,
        pub plaintext: String,
        pub warning: bool,
    }
    pub fn all() -> serde_json::Value {
        serde_json::from_str(include_str!("channel_vectors.json")).unwrap()
    }
    pub fn get(name: &str) -> Vector {
        serde_json::from_value(
            all()["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == name)
                .unwrap()
                .clone(),
        )
        .unwrap()
    }
    pub fn bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    pub fn frame(vector: &Vector) -> Vec<u8> {
        let mut frame = vec![
            0x88,
            0x10,
            0xa1,
            vector.payload_type << 2 | 1,
            0,
            vector.channel_hash,
        ];
        frame.extend(bytes(&vector.mac));
        frame.extend(bytes(&vector.ciphertext));
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_vectors::{all, bytes, frame, get};

    #[test]
    fn independent_crypto_vectors_decode_with_byte_accurate_plaintext_trees() {
        for value in all()["vectors"].as_array().unwrap() {
            let vector: test_vectors::Vector = serde_json::from_value(value.clone()).unwrap();
            let wire = frame(&vector);
            let mut decoded = super::super::decode(&wire);
            apply_keys(
                &mut decoded,
                [(vector.name.clone(), bytes(&vector.key).try_into().unwrap())],
            );
            let ChannelStatus::Decrypted(plain) = &decoded.channel.as_ref().unwrap().status else {
                panic!("failed {}", vector.name);
            };
            assert_eq!(plain.bytes, bytes(&vector.plaintext), "{}", vector.name);
            assert_eq!(
                plain.warning.is_some(),
                vector.warning,
                "{}: {:?}",
                vector.name,
                plain.warning
            );
            super::super::tests::assert_structure(&plain.fields, 0..plain.bytes.len());
            super::super::tests::assert_structure(&decoded.structure, 0..wire.len());
            assert_eq!(
                &wire[decoded.channel.as_ref().unwrap().range.clone()],
                bytes(&vector.ciphertext)
            );
            assert!(
                decoded
                    .fields
                    .iter()
                    .any(|(name, value)| name == "Content" && value.starts_with("Decrypted"))
            );
        }
        let vector = get("binary_datagram");
        let plain = parse_plaintext(6, bytes(&vector.plaintext), vec![]);
        assert_eq!(plain.fields[2].name, "Data");
        assert_eq!(plain.fields[2].range, 3..8);
        assert_eq!(
            &plain.bytes[plain.fields[2].range.clone()],
            &[0, 0x61, 0, 0xff, 0]
        );
        assert_eq!(plain.fields[3].name, "Padding");
        let vector = get("aligned_text");
        assert_eq!(bytes(&vector.plaintext).len(), 16);
        assert!(
            parse_plaintext(5, bytes(&vector.plaintext), vec![])
                .fields
                .iter()
                .all(|field| field.name != "Padding")
        );
    }

    #[test]
    fn hash_collisions_aliases_and_double_mac_matches_do_not_pick_the_wrong_key() {
        let vector = get("public_text");
        let wire = frame(&vector);
        let key: [u8; 16] = bytes(&vector.key).try_into().unwrap();
        let wrong: [u8; 16] = bytes(all()["public_hash_collision_key"].as_str().unwrap())
            .try_into()
            .unwrap();
        use sha2::Digest;
        assert_eq!(sha2::Sha256::digest(wrong)[0], vector.channel_hash);
        let mut decoded = super::super::decode(&wire);
        apply_keys(&mut decoded, []);
        assert!(matches!(
            decoded.channel.as_ref().unwrap().status,
            ChannelStatus::NoKey
        ));
        apply_keys(&mut decoded, [("Wrong".into(), wrong)]);
        assert!(matches!(
            decoded.channel.as_ref().unwrap().status,
            ChannelStatus::MacMismatch
        ));
        apply_keys(
            &mut decoded,
            [
                ("Wrong".into(), wrong),
                ("Public".into(), key),
                ("Alias".into(), key),
                ("Public".into(), key),
            ],
        );
        let ChannelStatus::Decrypted(plain) = &decoded.channel.as_ref().unwrap().status else {
            panic!();
        };
        assert_eq!(plain.channels, vec!["Public", "Alias"]);
        assert_eq!(plain.bytes, bytes(&vector.plaintext));
        let values = all();
        let case = &values["ambiguous"];
        let a: [u8; 16] = bytes(case["keys"][0].as_str().unwrap()).try_into().unwrap();
        let b: [u8; 16] = bytes(case["keys"][1].as_str().unwrap()).try_into().unwrap();
        assert_ne!(a, b);
        assert_eq!(sha2::Sha256::digest(a)[0], sha2::Sha256::digest(b)[0]);
        let mut envelope = ChannelEnvelope::new(
            5,
            bytes(case["mac"].as_str().unwrap()).try_into().unwrap(),
            bytes(case["ciphertext"].as_str().unwrap()),
            0..16,
        );
        envelope.decrypt([("One".into(), a), ("Two".into(), b)]);
        assert!(matches!(&envelope.status, ChannelStatus::Ambiguous(groups) if groups.len() == 2));
    }

    #[test]
    fn changed_mac_ciphertext_and_unaligned_blocks_never_produce_plaintext() {
        let vector = get("public_text");
        let key = bytes(&vector.key).try_into().unwrap();
        let mut mac: [u8; 2] = bytes(&vector.mac).try_into().unwrap();
        mac[0] ^= 1;
        let mut envelope = ChannelEnvelope::new(5, mac, bytes(&vector.ciphertext), 0..32);
        envelope.decrypt([("Public".into(), key)]);
        assert!(matches!(envelope.status, ChannelStatus::MacMismatch));
        let mut ciphertext = bytes(&vector.ciphertext);
        ciphertext[0] ^= 1;
        let mut envelope =
            ChannelEnvelope::new(5, bytes(&vector.mac).try_into().unwrap(), ciphertext, 0..32);
        envelope.decrypt([("Public".into(), key)]);
        assert!(matches!(envelope.status, ChannelStatus::MacMismatch));
        for length in [0, 1, 15, 17, 31, 33] {
            let mut envelope = ChannelEnvelope::new(5, [0; 2], vec![0; length], 0..length);
            envelope.decrypt([("Public".into(), key)]);
            assert!(matches!(envelope.status, ChannelStatus::Invalid(_)));
        }
    }

    #[test]
    fn arbitrary_plaintext_preserves_every_byte_and_partial_field_without_panics() {
        for length in 0..=184 {
            for byte in [0, 1, 4, 0x3a, 0x80, 0xff] {
                for ty in [5, 6] {
                    let plain = parse_plaintext(ty, vec![byte; length], vec![]);
                    super::super::tests::assert_structure(&plain.fields, 0..length);
                }
            }
        }
    }
}
