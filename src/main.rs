mod app;
mod ble;
mod catalogue;
mod companion;
mod connections;
mod discovery;
mod protocol;
mod source;
mod ui;
mod usb;

use anyhow::{Context, Result};
use clap::{ArgGroup, Parser};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use source::Source;
use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter},
    path::PathBuf,
    sync::{Arc, mpsc},
    time::Duration,
};

#[derive(Parser)]
#[command(version, about = "MeshCore raw RX packet inspector", group(ArgGroup::new("source").args(["serial", "tcp", "ble", "replay", "scan_ble"])))]
struct Args {
    /// USB companion serial port (omit all sources for connection picker)
    #[arg(long)]
    serial: Option<String>,
    #[arg(long, default_value_t = 115200)]
    baud: u32,
    /// Companion TCP host:port
    #[arg(long)]
    tcp: Option<String>,
    /// BLE companion name or identifier (discovered automatically)
    #[arg(long)]
    ble: Option<String>,
    /// Print BLE discovery results and adapter errors without opening the TUI
    #[arg(long)]
    scan_ble: bool,
    /// Open a previously recorded/exported JSONL capture
    #[arg(long)]
    replay: Option<PathBuf>,
    /// Maximum packets retained in memory
    #[arg(long, default_value_t = 10000, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    capacity: u32,
    /// Show companion messages and protocol details alongside radio packets
    #[arg(long)]
    show_companion: bool,
    /// Append all received companion frames to this JSONL file
    #[arg(long)]
    record: Option<PathBuf>,
    /// Destination for the e hotkey (appends a snapshot)
    #[arg(long, default_value = "meshages-export.jsonl")]
    export: PathBuf,
    /// Catalogue JSON path (default: user config directory/meshages/catalogue.json)
    #[arg(long)]
    catalogue: Option<PathBuf>,
}
struct Screen;
impl Screen {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        if let Err(e) = execute!(io::stdout(), EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(e.into());
        }
        Ok(Self)
    }
}
impl Drop for Screen {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
    }
}
fn pick(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    runtime: &Arc<tokio::runtime::Runtime>,
    baud: u32,
) -> Result<Option<(String, Source)>> {
    let (_watchers, updates) = connections::Watchers::start(baud, runtime.clone());
    let mut picker = connections::Picker::new();
    loop {
        for update in updates.try_iter() {
            picker.update(update);
        }
        let labels: Vec<_> = picker.choices().iter().map(|c| c.label.clone()).collect();
        let status = format!("{}\n{}", picker.usb_status, picker.ble_status);
        terminal.draw(|f| ui::picker(f, &labels, picker.index(), &status, picker.show_all_ble))?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Release {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(None),
                KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                    return Ok(None);
                }
                KeyCode::Up | KeyCode::Char('k') => picker.navigate(-1),
                KeyCode::Down | KeyCode::Char('j') => picker.navigate(1),
                KeyCode::Char('a') => picker.toggle_all(),
                KeyCode::Enter => {
                    if let Some(choice) = picker.selected() {
                        return Ok(Some((choice.label.clone(), choice.source.clone())));
                    }
                }
                _ => {}
            }
        }
    }
}
fn run(args: Args) -> Result<()> {
    let rt = Arc::new(ble::runtime()?);
    if args.scan_ble {
        println!("Discovering nearby and system-connected BLE devices…");
        let devices = rt.block_on(ble::scan())?;
        for device in &devices {
            println!("{}", device.label());
        }
        println!("{} BLE devices found", devices.len());
        return Ok(());
    }
    // Validate paths and replay before entering raw mode.
    let catalogue_path = match args.catalogue {
        Some(path) => path,
        None => catalogue::default_path()?,
    };
    let mut catalogue = Some(catalogue::Catalogue::load(catalogue_path)?);
    let mut replay = Vec::new();
    if let Some(path) = &args.replay {
        for (i, line) in BufReader::new(File::open(path)?).lines().enumerate() {
            let line = line?;
            if !line.trim().is_empty() {
                replay.push(
                    serde_json::from_str::<protocol::Capture>(&line)
                        .with_context(|| format!("Invalid capture at line {}", i + 1))?,
                );
            }
        }
    }
    let recording = args
        .record
        .as_ref()
        .map(|p| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .map(BufWriter::new)
        })
        .transpose()?;
    let initial = if let Some(port) = &args.serial {
        Some((
            format!("USB · {port}"),
            Source::Serial(port.clone(), args.baud),
        ))
    } else {
        args.tcp
            .as_ref()
            .map(|addr| (format!("TCP · {addr}"), Source::Tcp(addr.clone())))
    };
    let _screen = Screen::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut initial = initial;
    if let Some(query) = args.ble.as_ref() {
        terminal.draw(|f| ui::picker(f, &[], 0, "Scanning for requested BLE companion…", false))?;
        let devices = rt.block_on(ble::scan())?;
        let query = query.to_lowercase();
        let mut matches = devices
            .into_iter()
            .filter(|d| d.label().to_lowercase().contains(&query));
        let device = matches
            .next()
            .context("No matching BLE companion; run without arguments to use the picker")?;
        anyhow::ensure!(
            matches.next().is_none(),
            "Multiple BLE companions match; use a more specific identifier"
        );
        initial = Some((format!("BLE · {}", device.label()), Source::Ble(device)));
    }
    let mut recording = recording;
    loop {
        let choice = if args.replay.is_some() {
            None
        } else if initial.is_some() {
            initial.take()
        } else {
            pick(&mut terminal, &rt, args.baud)?
        };
        if choice.is_none() && args.replay.is_none() {
            break;
        }
        let label = choice
            .as_ref()
            .map(|(label, _)| label.clone())
            .unwrap_or_else(|| format!("REPLAY · {}", args.replay.as_ref().unwrap().display()));
        let mut app = app::App::new(
            label,
            args.capacity as usize,
            args.show_companion,
            args.export.clone(),
            catalogue.take().unwrap(),
        );
        app.catalogue.reset_device();
        app.recording = recording.take();
        let (tx, rx) = mpsc::sync_channel(2048);
        let worker = if let Some((_, source)) = choice {
            match source::start(source, tx) {
                Ok(w) => {
                    app.status =
                        "Connected · waiting for raw RX (BLE may still be connecting)".into();
                    Some(w)
                }
                Err(e) => {
                    app.status = format!("Connection failed: {e:#} · Esc to return to connections");
                    None
                }
            }
        } else {
            for packet in replay.drain(..) {
                app.push(packet)?;
            }
            app.status = "Replay complete".into();
            None
        };
        let mut quit = false;
        loop {
            for message in rx.try_iter().take(256) {
                match message {
                    source::Event::Packet(packet) => app.push(packet)?,
                    source::Event::Status(status) => app.status = status,
                }
            }
            terminal.draw(|f| ui::draw(f, &mut app))?;
            if event::poll(Duration::from_millis(50))?
                && let Event::Key(key) = event::read()?
            {
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                if key.code == KeyCode::Esc
                    && app.page == app::Page::Packets
                    && !app.expand_details
                    && app.catalogue_form.is_none()
                    && !app.help
                    && !app.editing
                    && app.filter.is_empty()
                    && args.replay.is_none()
                {
                    break;
                }
                match app.key(key) {
                    Ok(true) => {
                        quit = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(e) => app.status = format!("Action failed: {e:#}"),
                }
            }
        }
        drop(worker);
        recording = app.recording.take();
        catalogue = Some(app.catalogue);
        if quit || args.replay.is_some() {
            break;
        }
    }
    Ok(())
}
fn main() -> Result<()> {
    // Restore terminal even if a dependency panics.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        hook(info);
    }));
    run(Args::parse())
}
