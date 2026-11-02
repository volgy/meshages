//! Manual entries are persisted; built-in entries and device metadata stay in memory.
use anyhow::{Context, Result, ensure};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::PathBuf};

const PUBLIC_CHANNEL_KEY: &str = "8b3387e9c5cdea6ac9e5edbaa115cd72";

pub fn default_path() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("Cannot locate the user configuration directory; use --catalogue PATH")?
        .join("meshages")
        .join("catalogue.json"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Known {
    pub name: String,
    /// 128-bit key as hexadecimal, for a readable and portable file.
    pub key: String,
}
impl Known {
    pub fn public_channel() -> Self {
        Self {
            name: "Public".into(),
            key: PUBLIC_CHANNEL_KEY.into(),
        }
    }
    pub fn channel(name: &str, key: &str) -> Result<Self> {
        let name = name.trim();
        ensure!(
            !name.is_empty() && name.len() <= 64 && !name.chars().any(char::is_control),
            "Enter a channel name (up to 64 bytes)"
        );
        let key = if !key.trim().is_empty() {
            encode_key(&parse_key(key)?)
        } else if name == "Public" {
            PUBLIC_CHANNEL_KEY.into()
        } else {
            ensure!(
                name.starts_with('#') && name.len() > 1,
                "Enter a 32-digit hex key, or use #name for a public hashtag channel"
            );
            encode_key(&Sha256::digest(name.as_bytes())[..16])
        };
        Ok(Self {
            name: name.into(),
            key,
        })
    }
    pub fn region(name: &str) -> Result<Self> {
        let name = region_name(name)?;
        ensure!(
            !name.starts_with('$'),
            "Private regions are not supported; enter a public region name"
        );
        let key = encode_key(&Sha256::digest(format!("#{name}").as_bytes())[..16]);
        Ok(Self { name, key })
    }
    fn device_region(name: &str, key: &[u8]) -> Result<Self> {
        let name = region_name(name)?;
        ensure!(
            key.len() == 16 && key.iter().any(|&b| b != 0),
            "Invalid device region key"
        );
        let key = encode_key(key);
        Ok(Self { name, key })
    }
    pub fn bytes(&self) -> [u8; 16] {
        // All entries are validated on load and insertion.
        parse_key(&self.key).expect("validated catalogue key")
    }
    pub fn fingerprint(&self) -> String {
        format!("{}…", &self.key[..8])
    }
    pub fn transport_code(&self, payload_type: u8, payload: &[u8]) -> u16 {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.bytes()).expect("HMAC key length");
        mac.update(&[payload_type]);
        mac.update(payload);
        let digest = mac.finalize().into_bytes();
        match u16::from_le_bytes([digest[0], digest[1]]) {
            0 => 1,
            0xffff => 0xfffe,
            n => n,
        }
    }
    pub fn channel_hash(&self) -> u8 {
        Sha256::digest(self.bytes())[0]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Region,
    Channel,
}
impl Category {
    pub fn parse(self, name: &str, key: &str) -> Result<Known> {
        match self {
            Self::Region => {
                ensure!(
                    key.trim().is_empty(),
                    "Region keys are derived from the name"
                );
                Known::region(name)
            }
            Self::Channel => Known::channel(name, key),
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Region => "region",
            Self::Channel => "channel",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CatalogueEntry {
    pub value: Known,
    pub manual: bool,
    pub built_in: bool,
    pub device_default: bool,
    pub device_slots: Vec<u8>,
    /// Same name, different full keys. Never choose a winner or overwrite either entry.
    pub conflict: bool,
    /// Different names for the same key are aliases, not a key conflict.
    pub alias: bool,
}
impl CatalogueEntry {
    fn new(value: Known) -> Self {
        Self {
            value,
            manual: false,
            built_in: false,
            device_default: false,
            device_slots: vec![],
            conflict: false,
            alias: false,
        }
    }
    pub fn device(&self) -> bool {
        self.device_default || !self.device_slots.is_empty()
    }
    pub fn source(&self) -> &'static str {
        if self.built_in {
            return if self.device() {
                "built-in + device"
            } else {
                "built-in"
            };
        }
        match (self.manual, self.device()) {
            (true, true) => "manual + device",
            (true, false) => "manual",
            _ => "device (read-only)",
        }
    }
}

fn merge(
    manual: &[Known],
    built_in: &[Known],
    device: impl Iterator<Item = (Known, Option<u8>)>,
) -> Vec<CatalogueEntry> {
    let mut rows: Vec<_> = manual
        .iter()
        .cloned()
        .map(|value| CatalogueEntry {
            manual: true,
            ..CatalogueEntry::new(value)
        })
        .collect();
    for value in built_in {
        rows.push(CatalogueEntry {
            built_in: true,
            ..CatalogueEntry::new(value.clone())
        });
    }
    for (value, slot) in device {
        let index = rows
            .iter()
            .position(|r| r.value == value)
            .unwrap_or_else(|| {
                rows.push(CatalogueEntry::new(value));
                rows.len() - 1
            });
        let row = &mut rows[index];
        if let Some(slot) = slot {
            row.device_slots.push(slot);
        } else {
            row.device_default = true;
        }
    }
    rows.sort_by(|a, b| {
        a.value
            .name
            .cmp(&b.value.name)
            .then(a.value.key.cmp(&b.value.key))
    });
    let flags: Vec<_> = rows
        .iter()
        .map(|row| {
            (
                rows.iter().any(|other| {
                    row.value.name == other.value.name && row.value.key != other.value.key
                }),
                rows.iter().any(|other| {
                    row.value.key == other.value.key && row.value.name != other.value.name
                }),
            )
        })
        .collect();
    for (row, (conflict, alias)) in rows.iter_mut().zip(flags) {
        row.conflict = conflict;
        row.alias = alias;
        row.device_slots.sort_unstable();
    }
    rows
}

fn region_name(name: &str) -> Result<String> {
    let name = name.trim();
    let name = name.strip_prefix('#').unwrap_or(name);
    ensure!(
        !name.is_empty() && name.len() <= 64,
        "Enter a region name (up to 64 bytes)"
    );
    ensure!(
        name != "*" && !name.chars().any(|c| c.is_control() || c.is_whitespace()),
        "Region names cannot contain spaces or control characters; * means unscoped"
    );
    Ok(name.into())
}
fn parse_key(key: &str) -> Result<[u8; 16]> {
    let key: String = key.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    ensure!(
        key.len() == 32 && key.is_ascii(),
        "Key must contain exactly 32 hexadecimal digits"
    );
    let mut bytes = [0; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&key[i * 2..i * 2 + 2], 16)
            .context("Key must contain only hexadecimal digits")?;
    }
    Ok(bytes)
}
fn encode_key(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn name_bytes(bytes: &[u8]) -> Result<&str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let name = std::str::from_utf8(&bytes[..end]).context("Device returned a non-UTF-8 name")?;
    ensure!(
        !name.chars().any(char::is_control),
        "Device returned an invalid name"
    );
    Ok(name)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    version: u8,
    #[serde(default)]
    regions: Vec<String>,
    #[serde(default)]
    channels: Vec<Known>,
}
impl Default for Data {
    fn default() -> Self {
        Self {
            version: 1,
            regions: vec![],
            channels: vec![],
        }
    }
}

pub struct Catalogue {
    pub path: PathBuf,
    data: Data,
    default_region: Option<Known>,
    device_channels: Vec<(u8, Known)>,
    regions: Vec<CatalogueEntry>,
    channels: Vec<CatalogueEntry>,
}
impl Catalogue {
    pub fn load(path: PathBuf) -> Result<Self> {
        let mut data = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<Data>(&bytes)
                .with_context(|| format!("Reading catalogue {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Data::default(),
            Err(e) => return Err(e).with_context(|| format!("Reading {}", path.display())),
        };
        ensure!(
            data.version == 1,
            "Unsupported catalogue version {}",
            data.version
        );
        for name in &mut data.regions {
            *name = Known::region(name)?.name;
        }
        for entry in &mut data.channels {
            *entry = Known::channel(&entry.name, &entry.key)?;
        }
        // Public is always supplied by the built-in layer and needs no manual copy.
        data.channels
            .retain(|entry| entry != &Known::public_channel());
        data.regions.sort();
        data.regions.dedup();
        data.channels
            .sort_by(|a, b| a.name.cmp(&b.name).then(a.key.cmp(&b.key)));
        data.channels.dedup();
        let mut catalogue = Self {
            path,
            data,
            default_region: None,
            device_channels: vec![],
            regions: vec![],
            channels: vec![],
        };
        catalogue.rebuild();
        Ok(catalogue)
    }
    pub fn regions(&self) -> &[CatalogueEntry] {
        &self.regions
    }
    pub fn channels(&self) -> &[CatalogueEntry] {
        &self.channels
    }
    pub fn entries(&self, category: Category) -> &[CatalogueEntry] {
        match category {
            Category::Region => self.regions(),
            Category::Channel => self.channels(),
        }
    }
    fn rebuild(&mut self) {
        let manual_regions: Vec<_> = self
            .data
            .regions
            .iter()
            .map(|name| Known::region(name).expect("validated manual region name"))
            .collect();
        self.regions = merge(
            &manual_regions,
            &[],
            self.default_region.clone().map(|v| (v, None)).into_iter(),
        );
        self.channels = merge(
            &self.data.channels,
            &[Known::public_channel()],
            self.device_channels
                .iter()
                .map(|(slot, v)| (v.clone(), Some(*slot))),
        );
    }
    pub fn reset_device(&mut self) {
        self.default_region = None;
        self.device_channels.clear();
        self.rebuild();
    }
    pub fn annotate(&self, decoded: &mut crate::protocol::Decoded) {
        if let Some(scope) = &decoded.scope {
            let names: Vec<_> = self
                .regions()
                .iter()
                .filter(|r| {
                    r.value.transport_code(scope.payload_type, &scope.payload) == scope.code
                })
                .map(candidate_name)
                .collect();
            let value = if scope.code == 0 {
                "Unscoped / wildcard".into()
            } else if names.is_empty() {
                "No match in local catalogue".into()
            } else {
                decoded
                    .summary
                    .push_str(&format!(" · {}?", names.join(" / ")));
                format!(
                    "{} · 16-bit code match; collisions are possible",
                    names.join(" / ")
                )
            };
            decoded.fields.push(("Region candidates".into(), value));
        }
        if let Some(hash) = decoded.channel_hash {
            let names: Vec<_> = self
                .channels()
                .iter()
                .filter(|c| c.value.channel_hash() == hash)
                .map(candidate_name)
                .collect();
            if !names.is_empty() {
                decoded
                    .summary
                    .push_str(&format!(" · {}?", names.join(" / ")));
                decoded.fields.push((
                    "Channel candidates".into(),
                    format!(
                        "{} · 8-bit hash match; content not verified",
                        names.join(" / ")
                    ),
                ));
            }
        }
    }
    fn save(&self, data: &Data) -> Result<()> {
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        fs::create_dir_all(parent)?;
        // Persist by replacing a complete file. A failed write leaves the old catalogue intact.
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer_pretty(&mut file, data)?;
        writeln!(file)?;
        file.as_file().sync_all()?;
        file.persist(&self.path)
            .with_context(|| format!("Saving catalogue {}", self.path.display()))?;
        Ok(())
    }
    fn insert(&mut self, entry: Known, category: Category) -> Result<bool> {
        ensure!(
            category != Category::Channel || entry != Known::public_channel(),
            "Public is already available as a read-only built-in channel"
        );
        let mut next = self.data.clone();
        if category == Category::Channel {
            if next.channels.contains(&entry) {
                return Ok(false);
            }
            next.channels.push(entry);
            next.channels
                .sort_by(|a, b| a.name.cmp(&b.name).then(a.key.cmp(&b.key)));
        } else {
            if next.regions.contains(&entry.name) {
                return Ok(false);
            }
            next.regions.push(entry.name);
            next.regions.sort();
        }
        self.save(&next)?;
        self.data = next;
        self.rebuild();
        Ok(true)
    }
    pub fn add_region(&mut self, name: &str) -> Result<bool> {
        self.add(Category::Region, name, "")
    }
    pub fn add(&mut self, category: Category, name: &str, key: &str) -> Result<bool> {
        self.insert(category.parse(name, key)?, category)
    }
    pub fn remove(&mut self, category: Category, index: usize) -> Result<()> {
        let entry = self
            .entries(category)
            .get(index)
            .context("No entry selected")?;
        ensure!(
            entry.manual && !entry.built_in,
            "Built-in and device entries are read-only; only manual copies can be removed"
        );
        let value = &entry.value;
        let mut next = self.data.clone();
        if category == Category::Region {
            next.regions.retain(|name| name != &value.name);
        } else {
            next.channels.retain(|v| v != value);
        }
        self.save(&next)?;
        self.data = next;
        self.rebuild();
        Ok(())
    }
    /// Updates session metadata only. This method never creates or writes the local file.
    pub fn ingest(&mut self, frame: &[u8]) -> Result<bool> {
        match frame.first() {
            Some(0x1c) if frame.len() == 1 => {
                let changed = self.default_region.take().is_some();
                self.rebuild();
                Ok(changed)
            }
            Some(0x1c) => {
                ensure!(frame.len() == 48, "Truncated default region response");
                let entry = Known::device_region(name_bytes(&frame[1..32])?, &frame[32..48])?;
                let changed = self.default_region.as_ref() != Some(&entry);
                self.default_region = Some(entry);
                self.rebuild();
                Ok(changed)
            }
            Some(0x12) => {
                ensure!(frame.len() == 50, "Truncated channel response");
                let name = name_bytes(&frame[2..34])?;
                let entry = (!name.is_empty()).then(|| Known {
                    name: name.into(),
                    key: encode_key(&frame[34..50]),
                });
                let previous = self
                    .device_channels
                    .iter()
                    .find(|(slot, _)| *slot == frame[1])
                    .map(|(_, v)| v);
                let changed = previous != entry.as_ref();
                self.device_channels.retain(|(slot, _)| *slot != frame[1]);
                if let Some(entry) = entry {
                    self.device_channels.push((frame[1], entry));
                }
                self.rebuild();
                Ok(changed)
            }
            _ => Ok(false),
        }
    }
}

fn candidate_name(entry: &CatalogueEntry) -> String {
    if entry.conflict {
        format!("{} ({})", entry.value.name, entry.value.fingerprint())
    } else {
        entry.value.name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn extra_channels(catalogue: &Catalogue) -> Vec<&CatalogueEntry> {
        catalogue
            .channels()
            .iter()
            .filter(|entry| !entry.built_in)
            .collect()
    }
    #[test]
    fn public_is_always_available_read_only_and_never_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalogue.json");
        let mut c = Catalogue::load(path.clone()).unwrap();
        assert_eq!(c.channels().len(), 1);
        let public = &c.channels()[0];
        assert_eq!(public.value, Known::public_channel());
        assert!(public.built_in && !public.manual && !public.device());
        assert!(c.remove(Category::Channel, 0).is_err());
        assert!(c.add(Category::Channel, "Public", "").is_err());
        assert!(!path.exists());
        let mut decoded = crate::protocol::decode(&[0x88, 0, 150, 0x15, 0, 0x11, 1, 2, 3]);
        c.annotate(&mut decoded);
        assert!(
            decoded
                .fields
                .iter()
                .any(|(key, value)| key == "Channel candidates" && value.contains("Public"))
        );
        c.add_region("test").unwrap();
        let data: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(data["channels"], serde_json::json!([]));
        c.reset_device();
        assert_eq!(c.channels().len(), 1);
        assert!(c.channels()[0].built_in);
    }
    #[test]
    fn public_merges_by_name_and_key_and_not_by_device_slot() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Catalogue::load(dir.path().join("catalogue.json")).unwrap();
        let mut frame = vec![0; 50];
        frame[0] = 0x12;
        frame[1] = 7;
        frame[2..8].copy_from_slice(b"Public");
        frame[34..].copy_from_slice(&Known::public_channel().bytes());
        assert!(c.ingest(&frame).unwrap());
        assert_eq!(c.channels().len(), 1);
        assert_eq!(c.channels()[0].source(), "built-in + device");
        assert_eq!(c.channels()[0].device_slots, [7]);
        assert!(c.remove(Category::Channel, 0).is_err());
        frame[1] = 0;
        frame[34..].fill(1); // slot zero may hold a different key
        c.ingest(&frame).unwrap();
        assert_eq!(c.channels().len(), 2);
        assert!(c.channels().iter().all(|entry| entry.conflict));
        let builtin = c.channels().iter().find(|entry| entry.built_in).unwrap();
        assert_eq!(builtin.device_slots, [7]);
        frame[1] = 7;
        frame[2..34].fill(0);
        c.ingest(&frame).unwrap();
        assert!(
            !c.channels()
                .iter()
                .find(|entry| entry.built_in)
                .unwrap()
                .device()
        );
        c.reset_device();
        assert_eq!(c.channels().len(), 1);
        assert_eq!(c.channels()[0].source(), "built-in");
    }
    #[test]
    fn region_hashes_match_independent_sha256_hmac_vectors() {
        // Calculated independently with Python hashlib/hmac, matching the firmware's
        // SHA256("#test")[..16] and HMAC(key, type || payload)[..2] in little endian.
        let region = Known::region("test").unwrap();
        assert_eq!(region.key, "9cd8fcf22a47333b591d96a2b848b73f");
        assert_eq!(region.transport_code(3, &[1, 2, 3, 4]), 0xf3f4);
        assert_eq!(region.channel_hash(), 0xd9);
        assert_ne!(Known::region("Test").unwrap(), region);
    }
    #[test]
    fn matches_remain_candidates_when_multiple_catalogue_entries_match() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Catalogue::load(dir.path().join("catalogue.json")).unwrap();
        c.add_region("test").unwrap();
        // Independently found SHA256/HMAC collision for this packet's 16-bit code.
        c.add_region("alias-23301").unwrap();
        let mut decoded =
            crate::protocol::decode(&[0x88, 0, 150, 12, 0xf4, 0xf3, 0, 0, 0, 1, 2, 3, 4]);
        c.annotate(&mut decoded);
        let candidates = decoded
            .fields
            .iter()
            .find(|(k, _)| k == "Region candidates")
            .unwrap();
        assert!(candidates.1.contains("alias-23301 / test"));
        assert!(candidates.1.contains("collisions"));
        assert!(decoded.summary.contains('?'));
    }
    #[test]
    fn device_entries_are_read_only_and_never_written_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalogue.json");
        let mut c = Catalogue::load(path.clone()).unwrap();
        let mut frame = vec![0; 48];
        frame[0] = 0x1c;
        frame[1..6].copy_from_slice(b"#test");
        frame[32..].fill(42);
        assert!(c.ingest(&frame).unwrap());
        assert!(!c.ingest(&frame).unwrap());
        assert!(c.regions()[0].device_default);
        assert_eq!(c.regions()[0].value.key, "2a".repeat(16));
        assert!(!c.regions()[0].manual);
        assert!(c.remove(Category::Region, 0).is_err());
        assert!(!path.exists());
        // In-memory imports work even if no local file can be written.
        let mut channel = vec![0; 50];
        channel[0] = 0x12;
        channel[2..6].copy_from_slice(b"test");
        channel[34..].fill(1);
        assert!(c.ingest(&channel).unwrap());
        let slot = c
            .channels()
            .iter()
            .position(|entry| entry.value.name == "test")
            .unwrap();
        assert!(c.remove(Category::Channel, slot).is_err());
        assert!(!path.exists());
        c.add_region("manual").unwrap();
        let saved: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["regions"], serde_json::json!(["manual"]));
        let restored = Catalogue::load(path).unwrap();
        assert_eq!(restored.regions().len(), 1);
        assert_eq!(restored.regions()[0].value.name, "manual");
        assert!(extra_channels(&restored).is_empty());
        c.reset_device();
        assert_eq!(c.regions().len(), 1);
        assert!(extra_channels(&c).is_empty());
    }
    #[test]
    fn device_channel_slots_replace_and_clear_session_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Catalogue::load(dir.path().join("catalogue.json")).unwrap();
        let mut f = vec![0; 50];
        f[0] = 0x12;
        f[1] = 3;
        assert!(!c.ingest(&f).unwrap());
        f[2..6].copy_from_slice(b"test");
        f[34..].fill(1);
        assert!(c.ingest(&f).unwrap());
        assert!(!c.ingest(&f).unwrap());
        f[34..].fill(2);
        assert!(c.ingest(&f).unwrap());
        assert_eq!(extra_channels(&c).len(), 1);
        assert_eq!(extra_channels(&c)[0].value.key, "02".repeat(16));
        assert_eq!(c.device_channels.len(), 1);
        let mut second = f.clone();
        second[1] = 4;
        assert!(c.ingest(&second).unwrap());
        assert_eq!(extra_channels(&c).len(), 1);
        assert_eq!(extra_channels(&c)[0].device_slots, [3, 4]);
        second[2..34].fill(0);
        assert!(c.ingest(&second).unwrap());
        assert_eq!(extra_channels(&c)[0].device_slots, [3]);
        c.reset_device();
        assert!(c.device_channels.is_empty());
        assert!(extra_channels(&c).is_empty());
    }
    #[test]
    fn manual_and_device_duplicates_merge_and_removing_manual_keeps_device() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalogue.json");
        let mut c = Catalogue::load(path.clone()).unwrap();
        let mut frame = vec![0; 48];
        frame[0] = 0x1c;
        frame[1..6].copy_from_slice(b"#test");
        let region = Known::region("test").unwrap();
        frame[32..].copy_from_slice(&region.bytes());
        c.ingest(&frame).unwrap();
        assert!(c.add_region("test").unwrap());
        assert!(!c.add_region("#test").unwrap());
        assert_eq!(c.regions().len(), 1);
        assert_eq!(c.regions()[0].source(), "manual + device");
        c.remove(Category::Region, 0).unwrap();
        assert_eq!(c.regions().len(), 1);
        assert_eq!(c.regions()[0].source(), "device (read-only)");
        assert!(Catalogue::load(path).unwrap().regions().is_empty());
        c.reset_device();
        assert!(c.regions().is_empty());
    }
    #[test]
    fn channel_crud_preserves_conflicts_aliases_and_manual_data_across_devices() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalogue.json");
        let mut c = Catalogue::load(path.clone()).unwrap();
        assert!(c.add(Category::Channel, "test", &"01".repeat(16)).unwrap());
        assert!(c.add(Category::Channel, "alias", &"01".repeat(16)).unwrap());
        let before = fs::read(&path).unwrap();
        let mut f = vec![0; 50];
        f[0] = 0x12;
        f[1] = 3;
        f[2..6].copy_from_slice(b"test");
        f[34..].fill(2);
        c.ingest(&f).unwrap();
        assert_eq!(fs::read(&path).unwrap(), before); // import cannot rewrite manual data
        assert_eq!(extra_channels(&c).len(), 3);
        assert_eq!(extra_channels(&c).iter().filter(|e| e.conflict).count(), 2);
        assert_eq!(extra_channels(&c).iter().filter(|e| e.alias).count(), 2);
        assert_eq!(extra_channels(&c).iter().filter(|e| !e.manual).count(), 1);
        f[34..].fill(1);
        c.ingest(&f).unwrap();
        assert_eq!(extra_channels(&c).len(), 2);
        assert_eq!(extra_channels(&c)[1].source(), "manual + device");
        let index = c
            .channels()
            .iter()
            .position(|entry| entry.value.name == "test")
            .unwrap();
        c.remove(Category::Channel, index).unwrap();
        assert_eq!(extra_channels(&c).len(), 2); // the device row remains
        c.reset_device();
        assert_eq!(extra_channels(&c).len(), 1);
        let restored = Catalogue::load(path).unwrap();
        assert_eq!(extra_channels(&restored)[0].value.name, "alias");
    }
    #[test]
    fn channel_names_derive_hashtag_and_public_keys_but_custom_names_need_keys() {
        assert_eq!(
            Known::channel("#test", "").unwrap().key,
            Known::region("test").unwrap().key
        );
        assert_eq!(
            Known::channel("Public", "").unwrap().bytes(),
            [
                0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a, 0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15,
                0xcd, 0x72
            ]
        );
        assert!(Known::channel("private", "").is_err());
        assert!(Known::channel("#", "").is_err());
        assert!(Known::channel("", &"01".repeat(16)).is_err());
        assert!(Known::channel("private", "not hex").is_err());
    }
    #[test]
    fn same_short_key_fingerprint_does_not_merge_different_full_keys() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Catalogue::load(dir.path().join("catalogue.json")).unwrap();
        c.add(
            Category::Channel,
            "same",
            "12345678000000000000000000000001",
        )
        .unwrap();
        c.add(
            Category::Channel,
            "same",
            "12345678000000000000000000000002",
        )
        .unwrap();
        assert_eq!(extra_channels(&c).len(), 2);
        assert_eq!(
            extra_channels(&c)[0].value.fingerprint(),
            extra_channels(&c)[1].value.fingerprint()
        );
        assert!(extra_channels(&c).iter().all(|r| r.conflict));
        assert!(!extra_channels(&c).iter().any(|r| r.alias));
    }
    #[test]
    fn rejects_invalid_file_private_regions_and_manual_region_key_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalogue.json");
        fs::write(&path, b"not json").unwrap();
        assert!(Catalogue::load(path.clone()).is_err());
        assert_eq!(fs::read(path).unwrap(), b"not json");
        assert!(Known::region("$private").is_err());
        assert!(Known::region("#").is_err());
        assert!(Category::Region.parse("test", &"01".repeat(16)).is_err());
        assert_eq!(
            Known::region("test").unwrap(),
            Known::region("#test").unwrap()
        );
    }
    #[test]
    fn save_failure_preserves_previous_in_memory_catalogue() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Catalogue::load(dir.path().join("catalogue.json")).unwrap();
        c.add_region("test").unwrap();
        let original = fs::read(&c.path).unwrap();
        // A directory cannot be replaced by a catalogue file.
        c.path = dir.path().join("directory");
        fs::create_dir(&c.path).unwrap();
        assert!(c.add_region("other").is_err());
        assert_eq!(c.regions().len(), 1);
        assert_eq!(
            fs::read(dir.path().join("catalogue.json")).unwrap(),
            original
        );
    }
}
