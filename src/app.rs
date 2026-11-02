use crate::catalogue::{Catalogue, CatalogueEntry, Category, Known};
use crate::protocol::{Capture, Decoded, decode};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;
use std::{
    collections::VecDeque,
    fs::OpenOptions,
    io::{BufWriter, Write},
    path::PathBuf,
};

pub struct Entry {
    pub id: u64,
    pub capture: Capture,
    pub decoded: Decoded,
}
impl Entry {
    pub fn detail_fields(&self, show_companion: bool) -> impl Iterator<Item = &(String, String)> {
        self.decoded
            .fields
            .iter()
            .filter(move |(key, _)| show_companion || key != "Companion type")
    }
    pub fn detail_bytes(&self, show_companion: bool) -> &[u8] {
        if show_companion {
            &self.capture.frame
        } else {
            self.capture.frame.get(3..).unwrap_or_default()
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Packets,
    Regions,
    Channels,
}
pub struct CatalogueForm {
    pub category: Category,
    pub name: String,
    pub key: String,
    pub focus_key: bool,
    pub error: String,
}
pub struct App {
    pub catalogue: Catalogue,
    pub page: Page,
    pub regions_table: TableState,
    pub channels_table: TableState,
    pub catalogue_form: Option<CatalogueForm>,
    pub entries: VecDeque<Entry>,
    pub visible: Vec<usize>,
    pub table: TableState,
    pub follow: bool,
    pub help: bool,
    pub help_colors: bool,
    pub filter: String,
    pub editing: bool,
    pub details: u16,
    pub focus_details: bool,
    pub expand_details: bool,
    pub status: String,
    pub source: String,
    pub total: u64,
    pub evicted: u64,
    pub limit: usize,
    pub show_companion: bool,
    pub export: PathBuf,
    pub recording: Option<BufWriter<std::fs::File>>,
}
impl App {
    pub fn new(
        source: String,
        limit: usize,
        show_companion: bool,
        export: PathBuf,
        catalogue: Catalogue,
    ) -> Self {
        Self {
            catalogue,
            page: Page::Packets,
            regions_table: TableState::default(),
            channels_table: TableState::default(),
            catalogue_form: None,
            entries: VecDeque::new(),
            visible: vec![],
            table: TableState::default(),
            follow: true,
            help: false,
            help_colors: false,
            filter: String::new(),
            editing: false,
            details: 0,
            focus_details: false,
            expand_details: false,
            status: "Waiting for packets".into(),
            source,
            total: 0,
            evicted: 0,
            limit,
            show_companion,
            export,
            recording: None,
        }
    }
    pub fn push(&mut self, capture: Capture) -> Result<()> {
        if let Some(writer) = self.recording.as_mut() {
            serde_json::to_writer(&mut *writer, &capture)?;
            writeln!(writer)?;
            writer.flush()?;
        }
        let region = self
            .catalogue_selected(Page::Regions)
            .map(|r| r.value.clone());
        let channel = self
            .catalogue_selected(Page::Channels)
            .map(|r| r.value.clone());
        match self.catalogue.ingest(&capture.frame) {
            Ok(true) => {
                self.restore_catalogue_selection(Page::Regions, region.as_ref());
                self.restore_catalogue_selection(Page::Channels, channel.as_ref());
                self.refresh_annotations();
                self.status = "Device metadata updated in memory".into();
            }
            Ok(false) => {}
            Err(e) => self.status = format!("Catalogue import failed: {e:#}"),
        }
        if !self.show_companion && capture.frame.first() != Some(&0x88) {
            return Ok(());
        }
        let selected = self.selected().map(|e| e.id);
        self.total += 1;
        let mut decoded = decode(&capture.frame);
        self.catalogue.annotate(&mut decoded);
        self.entries.push_back(Entry {
            id: self.total,
            capture,
            decoded,
        });
        if self.entries.len() > self.limit {
            self.entries.pop_front();
            self.evicted += 1;
        }
        self.refilter();
        if self.follow {
            self.table.select(self.visible.len().checked_sub(1));
            self.details = 0;
        } else if let Some(id) = selected {
            self.table.select(
                self.visible
                    .iter()
                    .position(|&i| self.entries[i].id == id)
                    .or_else(|| (!self.visible.is_empty()).then_some(0)),
            );
        }
        Ok(())
    }
    fn refresh_annotations(&mut self) {
        let selected = self.selected().map(|e| e.id);
        for entry in &mut self.entries {
            entry.decoded = decode(&entry.capture.frame);
            self.catalogue.annotate(&mut entry.decoded);
        }
        self.refilter();
        if self.follow {
            self.table.select(self.visible.len().checked_sub(1));
        } else if let Some(id) = selected {
            let index = self.visible.iter().position(|&i| self.entries[i].id == id);
            if index.is_some() {
                self.table.select(index);
            }
        }
    }
    pub fn catalogue_selected(&self, page: Page) -> Option<&CatalogueEntry> {
        match page {
            Page::Regions => self.catalogue.regions().get(self.regions_table.selected()?),
            Page::Channels => self
                .catalogue
                .channels()
                .get(self.channels_table.selected()?),
            Page::Packets => None,
        }
    }
    fn restore_catalogue_selection(&mut self, page: Page, selected: Option<&Known>) {
        let (entries, table) = match page {
            Page::Regions => (self.catalogue.regions(), &mut self.regions_table),
            Page::Channels => (self.catalogue.channels(), &mut self.channels_table),
            Page::Packets => return,
        };
        let index = selected
            .and_then(|e| entries.iter().position(|r| &r.value == e))
            .or_else(|| {
                (!entries.is_empty()).then(|| table.selected().unwrap_or(0).min(entries.len() - 1))
            });
        table.select(index);
    }
    fn catalogue_key(&mut self, key: KeyEvent) -> Result<()> {
        let category = if self.page == Page::Regions {
            Category::Region
        } else {
            Category::Channel
        };
        let (entries, table) = if self.page == Page::Regions {
            (self.catalogue.regions(), &mut self.regions_table)
        } else {
            (self.catalogue.channels(), &mut self.channels_table)
        };
        let delta = match key.code {
            KeyCode::Up | KeyCode::Char('k') => -1,
            KeyCode::Down | KeyCode::Char('j') => 1,
            KeyCode::PageUp => -10,
            KeyCode::PageDown => 10,
            KeyCode::Home | KeyCode::Char('g') => -(entries.len() as isize),
            KeyCode::End | KeyCode::Char('G') => entries.len() as isize,
            _ => 0,
        };
        if delta != 0 && !entries.is_empty() {
            table.select(Some(
                table
                    .selected()
                    .unwrap_or(0)
                    .saturating_add_signed(delta)
                    .min(entries.len() - 1),
            ));
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('1') => self.page = Page::Packets,
            KeyCode::Tab | KeyCode::BackTab => {
                self.page = if self.page == Page::Regions {
                    Page::Channels
                } else {
                    Page::Regions
                };
                self.restore_catalogue_selection(self.page, None);
            }
            KeyCode::Char('a' | 'n') => {
                self.catalogue_form = Some(CatalogueForm {
                    category,
                    name: String::new(),
                    key: String::new(),
                    focus_key: false,
                    error: String::new(),
                })
            }
            KeyCode::Delete | KeyCode::Char('d') => {
                let selected = if self.page == Page::Regions {
                    self.regions_table.selected()
                } else {
                    self.channels_table.selected()
                };
                if let Some(i) = selected {
                    let entry = self.catalogue.entries(category)[i].clone();
                    if entry.built_in || !entry.manual {
                        self.status =
                            "This entry is read-only · only manual entries can be removed".into();
                        return Ok(());
                    }
                    self.catalogue.remove(category, i)?;
                    self.restore_catalogue_selection(self.page, Some(&entry.value));
                    self.refresh_annotations();
                    self.status = format!(
                        "Removed manual copy of {}{}",
                        entry.value.name,
                        if entry.device() {
                            " · device entry remains visible"
                        } else {
                            ""
                        }
                    );
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn form_key(&mut self, key: KeyEvent) {
        let mut form = self.catalogue_form.take().unwrap();
        match key.code {
            KeyCode::Esc => return,
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down
                if form.category == Category::Channel =>
            {
                form.focus_key = !form.focus_key
            }
            KeyCode::Enter => match if form.category == Category::Region {
                self.catalogue.add_region(&form.name)
            } else {
                self.catalogue.add(form.category, &form.name, &form.key)
            } {
                Ok(true) => {
                    let entry = form.category.parse(&form.name, &form.key).unwrap();
                    self.restore_catalogue_selection(self.page, Some(&entry));
                    self.refresh_annotations();
                    self.status = format!("Added {} to local catalogue", entry.name);
                    return;
                }
                Ok(false) => form.error = "This name and key already have a manual entry".into(),
                Err(e) => form.error = format!("{e:#}"),
            },
            KeyCode::Backspace => {
                if form.focus_key {
                    form.key.pop();
                } else {
                    form.name.pop();
                }
                form.error.clear();
            }
            KeyCode::Char(c) if !c.is_control() => {
                let field = if form.focus_key {
                    &mut form.key
                } else {
                    &mut form.name
                };
                if field.len() < 128 {
                    field.push(c);
                }
                form.error.clear();
            }
            _ => {}
        }
        self.catalogue_form = Some(form);
    }
    pub fn refilter(&mut self) {
        let query = self.filter.to_lowercase();
        self.visible = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                query.is_empty()
                    || format!(
                        "{} {} {:?} {}",
                        e.decoded.kind,
                        e.decoded.summary,
                        e.detail_fields(self.show_companion).collect::<Vec<_>>(),
                        crate::protocol::hex(e.detail_bytes(self.show_companion))
                    )
                    .to_lowercase()
                    .contains(&query)
            })
            .map(|(i, _)| i)
            .collect();
        if self.visible.is_empty() {
            self.table.select(None);
        } else if self
            .table
            .selected()
            .is_none_or(|i| i >= self.visible.len())
        {
            self.table.select(Some(0));
        }
    }
    pub fn selected(&self) -> Option<&Entry> {
        self.visible
            .get(self.table.selected()?)
            .and_then(|&i| self.entries.get(i))
    }
    fn navigate(&mut self, delta: isize) {
        self.follow = false;
        if !self.visible.is_empty() {
            let i = self
                .table
                .selected()
                .unwrap_or(0)
                .saturating_add_signed(delta)
                .min(self.visible.len() - 1);
            self.table.select(Some(i));
        }
        self.details = 0;
    }
    pub fn key(&mut self, key: KeyEvent) -> Result<bool> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Ok(true);
        }
        if self.help {
            match key.code {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::F(1) => self.help = false,
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                    self.help_colors = !self.help_colors
                }
                _ => {}
            }
            return Ok(false);
        }
        if self.catalogue_form.is_some() {
            self.form_key(key);
            return Ok(false);
        }
        if self.editing {
            match key.code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.editing = false;
                }
                KeyCode::Enter => self.editing = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c) => self.filter.push(c),
                _ => {}
            }
            self.table.select(None);
            self.refilter();
            self.details = 0;
            return Ok(false);
        }
        match key.code {
            KeyCode::Char('r' | '2') => self.page = Page::Regions,
            KeyCode::Char('c' | '3') => self.page = Page::Channels,
            KeyCode::Char('1') => self.page = Page::Packets,
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Char('?') | KeyCode::F(1) => {
                self.help = true;
                self.help_colors = false;
                return Ok(false);
            }
            _ => {}
        }
        if self.page != Page::Packets {
            self.restore_catalogue_selection(
                self.page,
                self.catalogue_selected(self.page)
                    .map(|r| r.value.clone())
                    .as_ref(),
            );
            self.catalogue_key(key)?;
            return Ok(false);
        }
        match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Char('?') | KeyCode::F(1) => self.help = true,
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus_details = self.expand_details || !self.focus_details;
            }
            KeyCode::Enter => {
                self.expand_details = !self.expand_details;
                self.focus_details = self.expand_details;
                if self.expand_details {
                    self.follow = false;
                }
            }
            KeyCode::Char('/') => {
                self.editing = true;
                self.follow = false;
            }
            KeyCode::Esc if self.expand_details => {
                self.expand_details = false;
                self.focus_details = false;
            }
            KeyCode::Esc => {
                self.filter.clear();
                self.refilter();
            }
            KeyCode::Up | KeyCode::Char('k') if self.focus_details => {
                self.details = self.details.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') if self.focus_details => {
                self.details = self.details.saturating_add(1)
            }
            KeyCode::Up | KeyCode::Char('k') => self.navigate(-1),
            KeyCode::Down | KeyCode::Char('j') => self.navigate(1),
            KeyCode::PageUp => {
                if self.focus_details {
                    self.details = self.details.saturating_sub(10);
                } else {
                    self.navigate(-10);
                }
            }
            KeyCode::PageDown => {
                if self.focus_details {
                    self.details = self.details.saturating_add(10);
                } else {
                    self.navigate(10);
                }
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.navigate(-(self.visible.len() as isize));
            }
            KeyCode::End | KeyCode::Char('G') | KeyCode::Char('f') => {
                self.follow = true;
                self.table.select(self.visible.len().checked_sub(1));
                self.details = 0;
            }
            KeyCode::Char(' ') => {
                self.follow = !self.follow;
                if self.follow {
                    self.table.select(self.visible.len().checked_sub(1));
                    self.details = 0;
                }
            }
            KeyCode::Char('e') => self.export()?,
            _ => {}
        }
        Ok(false)
    }
    fn export(&mut self) -> Result<()> {
        // Append a snapshot, preserving existing captures rather than overwriting them.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.export)?;
        let mut writer = BufWriter::new(file);
        for &i in &self.visible {
            serde_json::to_writer(&mut writer, &self.entries[i].capture)?;
            writeln!(writer)?;
        }
        writer.flush()?;
        self.status = format!(
            "Exported {} visible packets → {} (appended)",
            self.visible.len(),
            self.export.display()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn press(app: &mut App, code: KeyCode) {
        assert!(!app.key(KeyEvent::new(code, KeyModifiers::NONE)).unwrap());
    }
    #[test]
    fn empty_catalogue_navigation_manual_add_validation_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            "test".into(),
            10,
            false,
            "unused".into(),
            Catalogue::load(dir.path().join("catalogue.json")).unwrap(),
        );
        press(&mut app, KeyCode::Char('r'));
        assert!(app.page == Page::Regions);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Char('d'));
        press(&mut app, KeyCode::Tab);
        assert!(app.page == Page::Channels);
        press(&mut app, KeyCode::Esc);
        assert!(app.page == Page::Packets);
        press(&mut app, KeyCode::Char('r'));
        press(&mut app, KeyCode::Char('a'));
        press(&mut app, KeyCode::Enter);
        assert!(!app.catalogue_form.as_ref().unwrap().error.is_empty());
        for c in "test".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Tab);
        assert!(!app.catalogue_form.as_ref().unwrap().focus_key);
        press(&mut app, KeyCode::Enter);
        assert!(app.catalogue_form.is_none());
        assert_eq!(app.catalogue.regions()[0].value.name, "test");
        press(&mut app, KeyCode::Delete);
        assert!(app.catalogue.regions().is_empty());
        press(&mut app, KeyCode::Char('a'));
        press(&mut app, KeyCode::Esc);
        assert!(app.page == Page::Regions && app.catalogue_form.is_none());
    }
    #[test]
    fn hidden_metadata_imports_and_refreshes_retained_packets_and_search() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            "test".into(),
            10,
            false,
            "unused".into(),
            Catalogue::load(dir.path().join("catalogue.json")).unwrap(),
        );
        app.filter = "test".into();
        app.push(Capture {
            at: chrono::Local::now(),
            frame: vec![0x88, 0, 150, 12, 0xf4, 0xf3, 0, 0, 0, 1, 2, 3, 4],
        })
        .unwrap();
        assert!(app.visible.is_empty());
        let mut frame = vec![0; 48];
        frame[0] = 0x1c;
        frame[1..6].copy_from_slice(b"#test");
        frame[32..].copy_from_slice(&Known::region("test").unwrap().bytes());
        app.push(Capture {
            at: chrono::Local::now(),
            frame,
        })
        .unwrap();
        assert_eq!(app.entries.len(), 1); // metadata stays hidden in the RX-only view
        assert_eq!(app.visible.len(), 1);
        assert!(app.selected().unwrap().decoded.summary.contains("test?"));
        press(&mut app, KeyCode::Char('r'));
        press(&mut app, KeyCode::Char('d'));
        assert_eq!(app.visible.len(), 1);
        assert_eq!(app.catalogue.regions().len(), 1);
        assert!(app.status.contains("read-only"));
        // Explicitly adding a manual copy merges sources; removing it preserves the device.
        press(&mut app, KeyCode::Char('a'));
        for c in "test".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.catalogue.regions()[0].source(), "manual + device");
        press(&mut app, KeyCode::Char('d'));
        assert_eq!(app.catalogue.regions()[0].source(), "device (read-only)");
        app.catalogue.reset_device();
        app.refresh_annotations();
        assert!(app.visible.is_empty());
        assert!(app.catalogue.regions().is_empty());
    }
    #[test]
    fn manual_channel_form_adds_and_removes_without_affecting_device_slots() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            "test".into(),
            10,
            false,
            "unused".into(),
            Catalogue::load(dir.path().join("catalogue.json")).unwrap(),
        );
        press(&mut app, KeyCode::Char('c'));
        press(&mut app, KeyCode::Delete);
        assert!(app.status.contains("read-only"));
        press(&mut app, KeyCode::Char('a'));
        for c in "custom".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);
        assert!(app.catalogue_form.as_ref().unwrap().error.contains("key"));
        press(&mut app, KeyCode::Tab);
        for c in "01".repeat(16).chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);
        assert!(app.catalogue_form.is_none());
        assert_eq!(
            app.catalogue_selected(Page::Channels).unwrap().value.name,
            "custom"
        );
        let mut frame = vec![0; 50];
        frame[0] = 0x12;
        frame[1] = 2;
        frame[2..8].copy_from_slice(b"custom");
        frame[34..].fill(1);
        app.push(Capture {
            at: chrono::Local::now(),
            frame,
        })
        .unwrap();
        assert_eq!(
            app.catalogue_selected(Page::Channels).unwrap().source(),
            "manual + device"
        );
        press(&mut app, KeyCode::Delete);
        assert_eq!(
            app.catalogue_selected(Page::Channels).unwrap().source(),
            "device (read-only)"
        );
        press(&mut app, KeyCode::Delete);
        assert!(app.status.contains("read-only"));
        app.catalogue.reset_device();
        assert_eq!(app.catalogue.channels().len(), 1);
        assert!(app.catalogue.channels()[0].built_in);
    }
    fn packet(n: usize) -> Capture {
        Capture {
            at: chrono::Local::now(),
            frame: crate::protocol::sample_frame(n),
        }
    }
    #[test]
    fn inspection_stays_on_same_packet_until_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            "test".into(),
            3,
            false,
            "unused".into(),
            Catalogue::load(dir.path().join("catalogue.json")).unwrap(),
        );
        app.push(packet(0)).unwrap();
        app.push(packet(1)).unwrap();
        app.navigate(-1);
        app.push(packet(2)).unwrap();
        assert_eq!(app.selected().unwrap().id, 1);
        app.push(packet(3)).unwrap();
        assert_eq!(app.selected().unwrap().id, 2);
        assert_eq!(app.evicted, 1);
    }
    #[test]
    fn filtering_does_not_lose_capture() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            "test".into(),
            10,
            false,
            "unused".into(),
            Catalogue::load(dir.path().join("catalogue.json")).unwrap(),
        );
        app.filter = "ACK".into();
        app.push(packet(0)).unwrap();
        app.push(packet(3)).unwrap();
        assert_eq!(app.visible.len(), 1);
        assert_eq!(app.entries.len(), 2);
        assert_eq!(app.selected().unwrap().decoded.kind, "ACK");
    }
    #[test]
    fn search_obeys_display_mode_while_preserving_the_full_capture() {
        let frame = vec![0x88, 0x10, 0xa1, 0x0d, 0, 1, 2, 3, 4];
        for show_companion in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut app = App::new(
                "test".into(),
                10,
                show_companion,
                "unused".into(),
                Catalogue::load(dir.path().join("catalogue.json")).unwrap(),
            );
            app.push(Capture {
                at: chrono::Local::now(),
                frame: frame.clone(),
            })
            .unwrap();
            for query in ["Companion type", "88 10 A1"] {
                app.filter = query.into();
                app.refilter();
                assert_eq!(app.visible.len(), usize::from(show_companion));
            }
            app.filter = "0D 00 01 02 03 04".into();
            app.refilter();
            assert_eq!(app.visible.len(), 1);
            assert_eq!(app.selected().unwrap().capture.frame, frame);
        }
    }
}
