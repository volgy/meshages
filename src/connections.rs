//! Live connection picker state, keyed by device identity rather than row number.
use crate::{ble, source::Source, usb};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};

#[derive(Clone)]
pub struct Choice {
    pub id: String,
    pub label: String,
    pub relevant: bool,
    pub source: Source,
}
pub enum Update {
    Usb(Vec<Choice>, String),
    Ble(Vec<Choice>, String),
}
#[derive(Default)]
pub struct Picker {
    usb: Vec<Choice>,
    ble: Vec<Choice>,
    selected: Option<String>,
    pub show_all_ble: bool,
    pub usb_status: String,
    pub ble_status: String,
}
impl Picker {
    pub fn new() -> Self {
        Self {
            usb_status: "USB: checking companions…".into(),
            ble_status: "BLE: starting discovery…".into(),
            ..Default::default()
        }
    }
    pub fn choices(&self) -> Vec<&Choice> {
        self.usb
            .iter()
            .chain(self.ble.iter().filter(|d| self.show_all_ble || d.relevant))
            .collect()
    }
    pub fn index(&self) -> usize {
        self.choices()
            .iter()
            .position(|c| Some(&c.id) == self.selected.as_ref())
            .unwrap_or(0)
    }
    pub fn selected(&self) -> Option<&Choice> {
        self.choices()
            .into_iter()
            .find(|c| Some(&c.id) == self.selected.as_ref())
    }
    fn reconcile(&mut self, old_index: usize) {
        let choices = self.choices();
        if choices
            .iter()
            .any(|c| Some(&c.id) == self.selected.as_ref())
        {
            return;
        }
        self.selected = choices
            .get(old_index.min(choices.len().saturating_sub(1)))
            .map(|c| c.id.clone());
    }
    pub fn update(&mut self, update: Update) {
        let index = self.index();
        match update {
            Update::Usb(devices, status) => {
                self.usb = devices;
                self.usb_status = status;
            }
            Update::Ble(devices, status) => {
                self.ble = devices;
                self.ble_status = status;
            }
        }
        self.reconcile(index);
    }
    pub fn navigate(&mut self, delta: isize) {
        let choices = self.choices();
        let index = self
            .index()
            .saturating_add_signed(delta)
            .min(choices.len().saturating_sub(1));
        self.selected = choices.get(index).map(|c| c.id.clone());
    }
    pub fn toggle_all(&mut self) {
        let index = self.index();
        self.show_all_ble = !self.show_all_ble;
        self.reconcile(index);
    }
}

pub struct Watchers {
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}
impl Watchers {
    pub fn start(
        baud: u32,
        runtime: Arc<tokio::runtime::Runtime>,
    ) -> (Self, mpsc::Receiver<Update>) {
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let usb_tx = tx.clone();
        let usb_stop = stop.clone();
        let usb = std::thread::spawn(move || {
            usb::watch(baud, &usb_stop, |devices, status| {
                let choices = devices
                    .into_iter()
                    .map(|d| Choice {
                        id: format!("usb:{}", d.port),
                        label: format!("USB / {} · {}", d.port, d.description),
                        relevant: true,
                        source: Source::Serial(d.port, baud),
                    })
                    .collect();
                let _ = usb_tx.send(Update::Usb(choices, status));
            })
        });
        let ble_stop = stop.clone();
        let ble = std::thread::spawn(move || {
            runtime.block_on(ble::watch(&ble_stop, |snapshot| {
                let choices = snapshot
                    .devices
                    .into_iter()
                    .map(|d| Choice {
                        id: format!("ble:{}", d.id),
                        label: format!("BLE / {}", d.label()),
                        relevant: d.likely_companion,
                        source: Source::Ble(d),
                    })
                    .collect();
                let _ = tx.send(Update::Ble(choices, snapshot.status));
            }))
        });
        (
            Self {
                stop,
                threads: vec![usb, ble],
            },
            rx,
        )
    }
}
impl Drop for Watchers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn choice(id: &str, relevant: bool) -> Choice {
        Choice {
            id: id.into(),
            label: id.into(),
            relevant,
            source: Source::Tcp(id.into()),
        }
    }
    #[test]
    fn selection_survives_insertions_removal_and_metadata_updates() {
        let mut picker = Picker::new();
        picker.update(Update::Usb(
            vec![choice("b", true), choice("c", true)],
            String::new(),
        ));
        picker.navigate(1);
        picker.update(Update::Usb(
            vec![choice("a", true), choice("b", true), choice("c", true)],
            String::new(),
        ));
        assert_eq!(picker.selected().unwrap().id, "c");
        let mut renamed = choice("c", true);
        renamed.label = "updated device name".into();
        picker.update(Update::Usb(
            vec![choice("a", true), choice("b", true), renamed],
            String::new(),
        ));
        assert_eq!(picker.selected().unwrap().label, "updated device name");
        picker.update(Update::Usb(
            vec![choice("a", true), choice("b", true)],
            String::new(),
        ));
        assert_eq!(picker.selected().unwrap().id, "b");
        picker.update(Update::Usb(vec![], String::new()));
        assert!(picker.selected().is_none());
        picker.navigate(1);
        picker.navigate(-1);
        assert!(picker.selected().is_none());
    }
    #[test]
    fn filtering_and_hotplug_keep_selection_bound_to_the_correct_device() {
        let mut picker = Picker::new();
        picker.update(Update::Ble(
            vec![choice("radio", true), choice("tv", false)],
            String::new(),
        ));
        assert_eq!(picker.choices().len(), 1);
        picker.toggle_all();
        picker.navigate(1);
        assert_eq!(picker.selected().unwrap().id, "tv");
        picker.toggle_all();
        assert_eq!(picker.selected().unwrap().id, "radio");
        picker.update(Update::Usb(vec![choice("usb", true)], String::new()));
        assert_eq!(picker.selected().unwrap().id, "radio");
        picker.update(Update::Ble(vec![], String::new()));
        assert_eq!(picker.selected().unwrap().id, "usb");
    }
}
