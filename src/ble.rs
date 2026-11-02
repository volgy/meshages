use crate::{discovery::Nearby, protocol::Capture, source::Event};
use anyhow::{Context, Result};
use btleplug::{
    api::{
        Central, CentralEvent, CentralState, Manager as _, Peripheral as _,
        RetrievePeripheralsOptions, ScanFilter, WriteType,
    },
    platform::{Adapter, Manager, Peripheral},
};
use futures_util::{FutureExt, StreamExt};
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::SyncSender,
    },
    time::{Duration, Instant},
};
use uuid::Uuid;
const SERVICE: Uuid = Uuid::from_u128(0x6e400001_b5a3_f393_e0a9_e50e24dcca9e);
const RX: Uuid = Uuid::from_u128(0x6e400002_b5a3_f393_e0a9_e50e24dcca9e);
const TX: Uuid = Uuid::from_u128(0x6e400003_b5a3_f393_e0a9_e50e24dcca9e);

#[derive(Clone)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub peripheral: Peripheral,
    pub likely_companion: bool,
    pub rssi: Option<i16>,
    pub system: bool,
    advertising: bool,
}
impl Device {
    pub fn label(&self) -> String {
        let source = if self.system { "system" } else { "nearby" };
        let signal = self.rssi.map(|r| format!(" · {r} dBm")).unwrap_or_default();
        let hint = if self.likely_companion {
            ""
        } else {
            " · unverified"
        };
        format!("{} · {source}{signal}{hint} · {}", self.name, self.id)
    }
}
pub struct Snapshot {
    pub devices: Vec<Device>,
    pub status: String,
    pub error: bool,
}
pub fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

struct Session {
    adapter: Adapter,
    events: Pin<Box<dyn futures_util::Stream<Item = CentralEvent> + Send>>,
    nearby: Nearby<Device>,
    scanning: bool,
    next_system: Instant,
    status: String,
}
impl Session {
    async fn new(adapter: Adapter) -> Result<Self> {
        let events = adapter.events().await?;
        Ok(Self {
            adapter,
            events,
            nearby: Nearby::default(),
            scanning: false,
            next_system: Instant::now(),
            status: String::new(),
        })
    }
    async fn device(&self, peripheral: Peripheral, system: bool) -> Device {
        let id = peripheral.id().to_string();
        let old = self.nearby.get(&id);
        // Property snapshots can disappear mid-discovery as a device leaves range.
        let properties = peripheral.properties().await.unwrap_or_default();
        let advertising = properties
            .as_ref()
            .is_some_and(|p| p.advertisement_name.is_some() || p.rssi.is_some());
        let (name, services, rssi) = properties
            .map(|p| (p.advertisement_name.or(p.local_name), p.services, p.rssi))
            .unwrap_or_default();
        let name = name
            .filter(|n| !n.trim().is_empty())
            .or_else(|| old.map(|d| d.name.clone()))
            .unwrap_or_else(|| "Unnamed BLE device".into());
        let likely_companion = system
            || services.contains(&SERVICE)
            || name.to_lowercase().contains("meshcore")
            || old.is_some_and(|d| d.likely_companion);
        Device {
            id,
            name,
            peripheral,
            likely_companion,
            rssi,
            system,
            advertising,
        }
    }
    async fn tick(&mut self) -> Result<()> {
        let state = tokio::time::timeout(Duration::from_secs(2), self.adapter.adapter_state())
            .await
            .context("Bluetooth state query timed out")??;
        if state != CentralState::PoweredOn {
            if self.scanning {
                let _ = self.adapter.stop_scan().await;
            }
            self.scanning = false;
            self.nearby.clear();
            self.status = if state == CentralState::PoweredOff {
                "Bluetooth off; waiting"
            } else {
                "Bluetooth unavailable; waiting"
            }
            .into();
            return Ok(());
        }
        if !self.scanning {
            self.adapter.start_scan(ScanFilter::default()).await?;
            self.scanning = true;
            self.next_system = Instant::now();
        }
        if Instant::now() >= self.next_system {
            let retrieved = tokio::time::timeout(
                Duration::from_secs(8),
                self.adapter
                    .retrieve_peripherals(RetrievePeripheralsOptions {
                        services: Some(vec![SERVICE]),
                        identifiers: None,
                    }),
            )
            .await;
            match retrieved {
                Ok(Ok(peripherals)) => {
                    self.status.clear();
                    let mut devices = Vec::new();
                    for peripheral in peripherals {
                        let device = self.device(peripheral, true).await;
                        devices.push((device.id.clone(), device));
                    }
                    self.nearby.system_snapshot(devices, Instant::now());
                }
                Ok(Err(e)) => self.status = format!("System lookup: {e}"),
                Err(_) => self.status = "System lookup timed out; scanning continues".into(),
            }
            self.next_system = Instant::now() + Duration::from_secs(2);
        }
        // Only actual events renew advertisement presence. Enumerated caches do not.
        for _ in 0..256 {
            let Some(event) = self.events.next().now_or_never() else {
                break;
            };
            let Some(event) = event else {
                anyhow::bail!("Bluetooth event stream closed");
            };
            let definitely_advertising = matches!(
                &event,
                CentralEvent::ManufacturerDataAdvertisement { .. }
                    | CentralEvent::ServiceDataAdvertisement { .. }
                    | CentralEvent::ServicesAdvertisement { .. }
                    | CentralEvent::RssiUpdate { .. }
            );
            let id = match event {
                CentralEvent::DeviceDiscovered(id)
                | CentralEvent::DeviceUpdated(id)
                | CentralEvent::ManufacturerDataAdvertisement { id, .. }
                | CentralEvent::ServiceDataAdvertisement { id, .. }
                | CentralEvent::ServicesAdvertisement { id, .. }
                | CentralEvent::RssiUpdate { id, .. } => id,
                CentralEvent::DeviceDisconnected(_) => {
                    self.next_system = Instant::now();
                    continue;
                }
                _ => continue,
            };
            if let Ok(peripheral) = self.adapter.peripheral(&id).await {
                let device = self.device(peripheral, false).await;
                if definitely_advertising || device.advertising {
                    self.nearby
                        .advertised(device.id.clone(), device, Instant::now());
                }
            }
        }
        self.nearby.expire(Instant::now());
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let adapter = self.adapter.clone();
        tokio::spawn(async move {
            let _ = adapter.stop_scan().await;
        });
    }
}

async fn watch_session(mut update: impl FnMut(Snapshot)) -> Result<()> {
    let manager = Manager::new().await.context("Initializing Bluetooth")?;
    let adapters = tokio::time::timeout(Duration::from_secs(12), manager.adapters())
        .await
        .context("Bluetooth initialization timed out; check permissions")??;
    anyhow::ensure!(!adapters.is_empty(), "No Bluetooth adapter available");
    let mut sessions = Vec::new();
    for adapter in adapters {
        sessions.push(Session::new(adapter).await?);
    }
    loop {
        let mut devices = std::collections::BTreeMap::new();
        let mut errors = Vec::new();
        for session in &mut sessions {
            session.tick().await?;
            if !session.status.is_empty() {
                errors.push(session.status.clone());
            }
            for (device, system) in session.nearby.current(Instant::now()) {
                let mut device = device.clone();
                device.system = system;
                devices.entry(device.id.clone()).or_insert(device);
            }
        }
        let mut devices: Vec<_> = devices.into_values().collect();
        devices.sort_by_key(|d| (!d.likely_companion, d.name.to_lowercase(), d.id.clone()));
        let relevant = devices.iter().filter(|d| d.likely_companion).count();
        let status = if errors.is_empty() {
            format!(
                "BLE: {relevant} companions · {} other devices · watching",
                devices.len() - relevant
            )
        } else {
            format!("BLE: {}", errors.join("; "))
        };
        update(Snapshot {
            devices,
            status,
            error: !errors.is_empty(),
        });
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

/// Runs until the picker closes, retrying Bluetooth initialization after failures.
pub async fn watch(stop: &AtomicBool, mut update: impl FnMut(Snapshot)) {
    if stop.load(Ordering::Relaxed) {
        return;
    }
    let watching = Box::pin(async {
        loop {
            if let Err(e) = watch_session(&mut update).await {
                update(Snapshot {
                    devices: vec![],
                    status: format!("BLE: {e:#} · retrying"),
                    error: true,
                });
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    let cancelled = Box::pin(async {
        while !stop.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let _ = futures_util::future::select(watching, cancelled).await;
}

/// A bounded diagnostic/CLI discovery pass using the same watcher as the picker.
pub async fn scan() -> Result<Vec<Device>> {
    let mut snapshot = Snapshot {
        devices: vec![],
        status: "Bluetooth initialization timed out".into(),
        error: true,
    };
    let stop = AtomicBool::new(false);
    let _ = tokio::time::timeout(Duration::from_secs(12), watch(&stop, |s| snapshot = s)).await;
    if snapshot.error && snapshot.devices.is_empty() {
        anyhow::bail!("{}", snapshot.status);
    }
    Ok(snapshot.devices)
}

pub async fn listen(device: Device, tx: &SyncSender<Event>, stop: &AtomicBool) -> Result<()> {
    let p = device.peripheral;
    tokio::time::timeout(Duration::from_secs(20), p.connect())
        .await
        .context("BLE connection timed out")??;
    let result = async {
        p.discover_services().await?;
        let chars = p.characteristics();
        let rx = chars
            .iter()
            .find(|c| c.uuid == RX)
            .context("Companion RX characteristic missing")?;
        let notify = chars
            .iter()
            .find(|c| c.uuid == TX)
            .context("Companion TX characteristic missing")?;
        let mut stream = p.notifications().await?;
        p.subscribe(notify).await?;
        p.write(rx, &crate::companion::app_start(), WriteType::WithResponse)
            .await?;
        let mut startup = crate::companion::Startup::new(std::time::Instant::now());
        let _ = tx.try_send(Event::Status("BLE connected · listening for raw RX".into()));
        let mut dropped = 0;
        while !stop.load(Ordering::Relaxed) {
            match tokio::time::timeout(Duration::from_millis(150), stream.next()).await {
                Ok(Some(n)) if n.uuid == TX => {
                    if let Some(payload) = startup.step(Some(&n.value), std::time::Instant::now()) {
                        p.write(rx, &payload, WriteType::WithResponse).await?;
                    }
                    match tx.try_send(Event::Packet(Capture {
                        at: chrono::Local::now(),
                        frame: n.value,
                    })) {
                        Ok(()) => {}
                        Err(std::sync::mpsc::TrySendError::Full(_)) => dropped += 1,
                        Err(_) => break,
                    }
                }
                Ok(None) => anyhow::bail!("BLE notification stream closed"),
                _ => {}
            }
            if let Some(payload) = startup.step(None, std::time::Instant::now()) {
                p.write(rx, &payload, WriteType::WithResponse).await?;
            }
            if let Some(notice) = startup.notice.take() {
                let _ = tx.try_send(Event::Status(notice));
            }
            if !p.is_connected().await? {
                anyhow::bail!("BLE device disconnected");
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
        Ok(())
    }
    .await;
    let _ = p.disconnect().await;
    result
}
