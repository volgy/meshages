//! Compact packet inspection with semantic sections and byte coloring.
use super::{ACCENT, COMPANION, MUTED, PANEL, block, packet_color};
use crate::{
    app::{App, Entry},
    protocol::Route,
};
use ratatui::{prelude::*, widgets::*};

pub(super) const PAYLOAD: Color = Color::Rgb(214, 157, 245);
pub(super) const SCOPE: Color = Color::Rgb(151, 180, 255);
pub(super) const PATH: Color = Color::Rgb(110, 190, 239);
const GENERAL_BG: Color = Color::Rgb(24, 43, 48);
const PAYLOAD_BG: Color = Color::Rgb(34, 27, 46);
const LABEL_WIDTH: usize = 16;

fn clean(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { '�' } else { c })
        .collect()
}

/// Wrap values independently so continuation lines stay beneath the value column.
fn wrapped(value: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = vec![];
    let mut line = String::new();
    for word in value.split_whitespace() {
        let separator = usize::from(!line.is_empty());
        if Line::from(line.as_str()).width() + separator + Line::from(word).width() > width
            && !line.is_empty()
        {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        let span = Span::raw(word);
        for grapheme in span.styled_graphemes(Style::default()) {
            let grapheme_width = Line::from(grapheme.symbol).width();
            if Line::from(line.as_str()).width() + grapheme_width > width && !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            line.push_str(grapheme.symbol);
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

fn field(lines: &mut Vec<Line<'static>>, label: &str, value: &str, color: Color, width: usize) {
    let indent = LABEL_WIDTH.min(width / 2);
    let label_width = Line::from(label).width();
    let prefix = if label_width < indent {
        format!("{label}{}", " ".repeat(indent - label_width))
    } else {
        lines.push(Line::from(Span::styled(
            label.to_owned(),
            Style::default().fg(MUTED),
        )));
        " ".repeat(indent)
    };
    let value = clean(value);
    let empty = value.trim().is_empty();
    let value_style = if empty {
        Style::default().fg(MUTED).italic()
    } else {
        Style::default().fg(color)
    };
    for (index, value) in wrapped(
        if empty { "(empty)" } else { &value },
        width.saturating_sub(indent),
    )
    .into_iter()
    .enumerate()
    {
        lines.push(Line::from(vec![
            Span::styled(
                if index == 0 {
                    prefix.clone()
                } else {
                    " ".repeat(indent)
                },
                Style::default().fg(MUTED),
            ),
            Span::styled(value, value_style),
        ]));
    }
}

fn section(
    lines: &mut Vec<Line<'static>>,
    title: &str,
    note: &str,
    color: Color,
    background: Color,
    width: usize,
) {
    let title = format!(" {title} ");
    let note = if note.is_empty() {
        String::new()
    } else {
        format!(" {note} ")
    };
    let title_width = Line::from(title.as_str()).width();
    let used = title_width + Line::from(note.as_str()).width();
    let style = Style::default().fg(color).bg(background);
    // Keep a narrow pane's section title intact; put its metadata on the next row.
    let separate_note = used > width && !note.is_empty();
    let inline_note = if separate_note { "" } else { &note };
    lines.push(Line::from(vec![
        Span::styled(title, style.bold()),
        Span::styled(
            "─".repeat(width.saturating_sub(if separate_note { title_width } else { used })),
            style,
        ),
        Span::styled(inline_note.to_owned(), style),
    ]));
    if separate_note {
        for note in wrapped(note.trim(), width) {
            lines.push(Line::from(Span::styled(note, Style::default().fg(color))));
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    General,
    Identity,
    Envelope,
    Security,
    Content,
}
fn group(key: &str) -> Group {
    match key {
        "Companion type" | "SNR" | "RSSI" | "Header" | "Transport codes" | "Path"
        | "Trace SNR samples" | "Region candidates" | "Payload" => Group::General,
        "Name (unverified)"
        | "Node role"
        | "Location (unverified)"
        | "Advert timestamp"
        | "Public key" => Group::Identity,
        "Destination hash"
        | "Source hash"
        | "Ephemeral public key"
        | "Channel hash"
        | "Channel candidates" => Group::Envelope,
        "MAC" | "Signature" | "Verification" | "Auth code" => Group::Security,
        _ => Group::Content,
    }
}
fn label(key: &str) -> &str {
    match key {
        "Name (unverified)" => "Name",
        "Location (unverified)" => "Location",
        "Advert timestamp" => "Advertised",
        "Destination hash" => "Destination",
        "Source hash" => "Source",
        "Ephemeral public key" => "Ephemeral key",
        "Channel candidates" => "Channel",
        "Application data" => "Raw app data",
        _ => key,
    }
}
fn value_color(key: &str) -> Color {
    match key {
        "Name (unverified)"
        | "Node role"
        | "Location (unverified)"
        | "Public key"
        | "Ephemeral public key"
        | "Source hash"
        | "Destination hash" => PATH,
        "MAC" | "Auth code" | "Verification" => Color::Yellow,
        "Acknowledgment" => Color::Green,
        "Signature" => MUTED,
        "Channel hash" | "Channel candidates" | "Content" | "Body" | "Application data"
        | "Trace data" => PAYLOAD,
        _ => Color::White,
    }
}

fn document(entry: &Entry, show_companion: bool, width: usize) -> Vec<Line<'static>> {
    let d = &entry.decoded;
    let fields: Vec<_> = entry.detail_fields(show_companion).collect();
    let value = |key: &str| {
        fields
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    };
    let mut lines = vec![];
    if let Some(warning) = &d.warning {
        field(&mut lines, "⚠ Warning", warning, Color::Yellow, width);
    }
    section(
        &mut lines,
        "◈ GENERAL PACKET",
        "",
        ACCENT,
        GENERAL_BG,
        width,
    );
    if d.rssi.is_some() || d.snr.is_some() {
        lines.push(Line::from(vec![
            Span::styled("RSSI  ", Style::default().fg(MUTED)),
            Span::styled(
                value("RSSI").unwrap_or("—").to_owned(),
                Style::default().fg(Color::White).bold(),
            ),
            Span::styled("    SNR  ", Style::default().fg(MUTED)),
            Span::styled(
                value("SNR").unwrap_or("—").to_owned(),
                Style::default().fg(PATH).bold(),
            ),
        ]));
    }
    for (key, caption, color) in [
        ("Header", "Header", Color::White),
        ("Transport codes", "Scope codes", SCOPE),
        ("Region candidates", "Region", SCOPE),
        ("Path", "Path", PATH),
        ("Trace SNR samples", "Trace SNR", PATH),
        ("Companion type", "Companion type", COMPANION),
    ] {
        if let Some(value) = value(key) {
            field(&mut lines, caption, value, color, width);
        }
    }
    let radio = entry.capture.frame.first() == Some(&0x88);
    let payload_note = value("Payload").unwrap_or(if radio {
        "Unavailable"
    } else {
        "Companion body"
    });
    lines.push(Line::from(""));
    section(
        &mut lines,
        "▣ PAYLOAD",
        payload_note,
        PAYLOAD,
        PAYLOAD_BG,
        width,
    );
    let groups = [
        (Group::Identity, "Identity · unverified", PATH),
        (Group::Envelope, "Envelope", PAYLOAD),
        (Group::Content, "Content", PAYLOAD),
        (Group::Security, "Authentication fields", Color::Yellow),
    ];
    let active_groups = groups
        .iter()
        .filter(|(g, _, _)| fields.iter().any(|(key, _)| group(key) == *g))
        .count();
    let mut remaining = active_groups;
    for (kind, title, color) in groups {
        let mut selected: Vec<_> = fields
            .iter()
            .filter(|(key, _)| group(key) == kind)
            .collect();
        if selected.is_empty() {
            continue;
        }
        remaining -= 1;
        if kind == Group::Identity {
            selected.sort_by_key(|(key, _)| match key.as_str() {
                "Name (unverified)" => 0,
                "Node role" => 1,
                "Location (unverified)" => 2,
                "Advert timestamp" => 3,
                _ => 4,
            });
        }
        if active_groups > 1 {
            lines.push(Line::from(Span::styled(
                format!(" {} {title}", if remaining == 0 { "└─" } else { "├─" }),
                Style::default().fg(color).bold(),
            )));
        }
        for (key, raw_value) in selected {
            let formatted = if key == "Advert timestamp" {
                raw_value
                    .parse::<i64>()
                    .ok()
                    .and_then(|n| chrono::DateTime::from_timestamp(n, 0))
                    .map(|time| format!("{} · {raw_value}", time.format("%Y-%m-%d %H:%M:%S UTC")))
            } else {
                None
            };
            field(
                &mut lines,
                label(key),
                formatted.as_deref().unwrap_or(raw_value),
                value_color(key),
                width,
            );
        }
    }
    if active_groups == 0 {
        lines.push(Line::from(Span::styled(
            "No decoded payload fields; inspect the bytes below.",
            Style::default().fg(MUTED).italic(),
        )));
    }
    lines.push(Line::from(""));
    byte_dump(&mut lines, entry, show_companion, width);
    lines
}

fn scoped(entry: &Entry) -> bool {
    matches!(
        entry.decoded.route,
        Some(Route::ScopedFlood | Route::ScopedDirect)
    )
}
fn byte_color(entry: &Entry, show_companion: bool, offset: usize) -> Color {
    if entry.capture.frame.first() != Some(&0x88) {
        return COMPANION;
    }
    let prefix = if show_companion { 3 } else { 0 };
    if offset < prefix {
        return COMPANION;
    }
    let offset = offset - prefix;
    if offset == 0 {
        return ACCENT;
    }
    if scoped(entry) && offset < 5 {
        return SCOPE;
    }
    if let Some(payload) = &entry.decoded.payload_range {
        if offset < payload.start {
            return PATH;
        }
        if payload.contains(&offset) {
            return PAYLOAD;
        }
    }
    MUTED
}

fn byte_dump(lines: &mut Vec<Line<'static>>, entry: &Entry, show_companion: bool, width: usize) {
    section(
        lines,
        if show_companion {
            "⌗ WIRE BYTES / companion frame"
        } else {
            "⌗ RADIO BYTES / mesh packet"
        },
        "",
        PATH,
        GENERAL_BG,
        width,
    );
    let mut legend = vec![];
    if show_companion {
        legend.push(Span::styled(" Companion ", Style::default().fg(COMPANION)));
    }
    if entry.capture.frame.first() == Some(&0x88) {
        legend.push(Span::styled(" Header ", Style::default().fg(ACCENT)));
        if scoped(entry) {
            legend.push(Span::styled(" Scope ", Style::default().fg(SCOPE)));
        }
        legend.push(Span::styled(" Path ", Style::default().fg(PATH)));
        legend.push(Span::styled(" Payload ", Style::default().fg(PAYLOAD)));
    }
    lines.push(Line::from(legend));
    let columns = if width >= 71 {
        16
    } else if width >= 55 {
        12
    } else if width >= 39 {
        8
    } else {
        4
    };
    let bytes = entry.detail_bytes(show_companion);
    if bytes.is_empty() {
        lines.push(Line::from(Span::styled(
            "No bytes available.",
            Style::default().fg(MUTED),
        )));
    }
    for (row, chunk) in bytes.chunks(columns).enumerate() {
        let mut spans = vec![Span::styled(
            format!("{:04X}  ", row * columns),
            Style::default().fg(MUTED),
        )];
        for (index, byte) in chunk.iter().enumerate() {
            spans.push(Span::styled(
                format!(
                    "{byte:02X}{}",
                    if index + 1 == chunk.len() { "" } else { " " }
                ),
                Style::default().fg(byte_color(entry, show_companion, row * columns + index)),
            ));
        }
        spans.push(Span::raw(" ".repeat((columns - chunk.len()) * 3 + 2)));
        spans.push(Span::styled(
            chunk
                .iter()
                .map(|&b| {
                    if (32..127).contains(&b) {
                        b as char
                    } else {
                        '·'
                    }
                })
                .collect::<String>(),
            Style::default().fg(MUTED),
        ));
        lines.push(Line::from(spans));
    }
}

pub(super) fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let (title, overview, content) = if let Some(entry) = app.selected() {
        let d = &entry.decoded;
        let size = d.mesh_bytes.map_or_else(
            || {
                if app.show_companion {
                    format!("{} B companion", entry.capture.frame.len())
                } else {
                    "size unavailable".into()
                }
            },
            |n| format!("{n} B mesh"),
        );
        let mut badges = vec![Span::styled(
            clean(&d.kind),
            Style::default().fg(packet_color(entry)).bold(),
        )];
        if d.warning.is_some() {
            badges.push(Span::styled(
                "  ⚠ WARNING",
                Style::default().fg(Color::Yellow).bold(),
            ));
        }
        if d.fields.iter().any(|(key, _)| key == "Verification") {
            badges.push(Span::styled(
                "  UNVERIFIED",
                Style::default().fg(Color::Yellow),
            ));
        } else if d
            .fields
            .iter()
            .any(|(key, value)| key == "Content" && value.starts_with("Encrypted"))
        {
            badges.push(Span::styled("  ENCRYPTED", Style::default().fg(PAYLOAD)));
        }
        let overview = vec![
            Line::from(badges),
            Line::from(Span::styled(
                format!(
                    "Received {}",
                    entry.capture.at.format("%Y-%m-%d %H:%M:%S%.3f %:z")
                ),
                Style::default().fg(MUTED),
            )),
        ];
        (
            format!(" Packet #{:05} · {size} ", entry.id),
            overview,
            document(
                entry,
                app.show_companion,
                area.width.saturating_sub(2) as usize,
            ),
        )
    } else {
        (
            " Packet details ".into(),
            vec![],
            vec![Line::from("Select a packet to inspect its decoded fields.")],
        )
    };
    let border = block(title, app.focus_details);
    let inner = border.inner(area);
    if inner.width == 0 || inner.height == 0 {
        f.render_widget(border, area);
        return;
    }
    let header_height = if overview.is_empty() {
        0
    } else if inner.height >= 8 {
        2
    } else {
        1
    };
    let rows =
        Layout::vertical([Constraint::Length(header_height), Constraint::Min(1)]).split(inner);
    let paragraph = Paragraph::new(content).wrap(Wrap { trim: false });
    let content_height = paragraph.line_count(inner.width);
    let max = content_height
        .saturating_sub(rows[1].height as usize)
        .min(u16::MAX as usize) as u16;
    app.details = app.details.min(max);
    let border = if max > 0 {
        let end = (app.details as usize + rows[1].height as usize).min(content_height);
        border.title_bottom(
            Line::from(format!(
                " {}–{end} / {content_height} · {} ",
                usize::from(app.details) + 1,
                if app.focus_details {
                    "↑↓ scroll"
                } else {
                    "Tab to scroll"
                },
            ))
            .right_aligned()
            .style(Style::default().fg(MUTED)),
        )
    } else {
        border
    };
    f.render_widget(border, area);
    f.render_widget(
        Paragraph::new(overview).style(Style::default().bg(PANEL)),
        rows[0],
    );
    f.render_widget(paragraph.scroll((app.details, 0)), rows[1]);
    if max > 0 {
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            Rect::new(area.right().saturating_sub(1), rows[1].y, 1, rows[1].height),
            // Ratatui's scrollbar uses the number of scroll positions plus the viewport.
            &mut ScrollbarState::new(max as usize + 1)
                .viewport_content_length(rows[1].height as usize)
                .position(app.details as usize),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Capture, decode, sample_frame};
    use ratatui::backend::TestBackend;

    fn make_entry(frame: Vec<u8>) -> Entry {
        Entry {
            id: 1,
            decoded: decode(&frame),
            capture: Capture {
                at: chrono::DateTime::parse_from_rfc3339("2026-11-01T10:24:36.512-06:00")
                    .unwrap()
                    .into(),
                frame,
            },
        }
    }

    fn advert() -> Vec<u8> {
        let mut frame = vec![0x88, 0x1a, 0xa3, 0x10, 0x34, 0x12, 0x78, 0x56, 0x42];
        frame.extend_from_slice(&[0xa2, 0x17, 0xb9, 0x03]);
        frame.extend(0..32);
        frame.extend_from_slice(&1_793_544_000u32.to_le_bytes());
        frame.extend(0x80..0xc0);
        frame.push(0x92);
        frame.extend_from_slice(&51_507_351i32.to_le_bytes());
        frame.extend_from_slice(&(-127_758i32).to_le_bytes());
        frame.extend_from_slice(b"Hilltop repeater");
        frame
    }

    #[test]
    fn sections_preserve_all_decoded_values_at_different_widths() {
        let normalized = |s: &str| s.split_whitespace().collect::<String>();
        let mut frames: Vec<_> = (0..6).map(sample_frame).collect();
        frames.extend([
            advert(),
            vec![0x88],
            vec![0x88, 0, 150, 0x4c, 0x34, 0x12, 0x78, 0x56, 0, 1, 2, 3, 4],
            vec![0x88, 0, 150, 0x0d, 0xc0],
            vec![0x01, 0x02],
        ]);
        let mut unicode_advert = advert();
        unicode_advert.truncate(unicode_advert.len() - b"Hilltop repeater".len());
        unicode_advert.extend_from_slice("Rélais 東京 👩‍🚀\u{1b}[31m".as_bytes());
        frames.push(unicode_advert);
        for frame in frames {
            let entry = make_entry(frame);
            for show_companion in [false, true] {
                for width in [25, 43, 76, 118] {
                    let lines = document(&entry, show_companion, width);
                    let text = lines
                        .iter()
                        .map(Line::to_string)
                        .collect::<Vec<_>>()
                        .join("\n");
                    let general = text.find("GENERAL PACKET").unwrap();
                    let payload = text.find("PAYLOAD").unwrap();
                    let bytes = text.find("BYTES /").unwrap();
                    assert!(general < payload && payload < bytes);
                    for (_, value) in entry.detail_fields(show_companion) {
                        assert!(
                            normalized(&text).contains(&normalized(&clean(value))),
                            "lost {value}"
                        );
                    }
                    // The long advert name and full cryptographic fields must survive wrapping.
                    if text.contains("Hilltop") {
                        let name = text.find("Hilltop").unwrap();
                        let signature = text.find("Signature").unwrap();
                        assert!(payload < name && name < signature);
                    }
                }
            }
        }
    }

    #[test]
    fn byte_colors_follow_scope_path_and_payload_boundaries_in_both_modes() {
        let entry = make_entry(advert());
        assert_eq!(
            entry.decoded.payload_range,
            Some(10..entry.capture.frame.len() - 3)
        );
        for show_companion in [false, true] {
            let shift = if show_companion { 3 } else { 0 };
            for offset in 0..shift {
                assert_eq!(byte_color(&entry, show_companion, offset), COMPANION);
            }
            for offset in 0..entry.capture.frame.len() - 3 {
                let expected = match offset {
                    0 => ACCENT,
                    1..=4 => SCOPE,
                    5..=9 => PATH,
                    _ => PAYLOAD,
                };
                assert_eq!(byte_color(&entry, show_companion, offset + shift), expected);
            }
        }
        let truncated = make_entry(vec![0x88, 0, 150, 0x0d, 0xc0]);
        assert!(truncated.decoded.payload_range.is_none());
        assert_eq!(byte_color(&truncated, false, 1), MUTED);
        let companion = make_entry(vec![0x01, 0x02]);
        assert_eq!(byte_color(&companion, true, 0), COMPANION);
    }

    #[test]
    fn scrolling_and_resize_reach_last_byte_without_losing_packet_context() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            "Test capture".into(),
            100,
            false,
            "unused".into(),
            crate::catalogue::Catalogue::load(dir.path().join("catalogue.json")).unwrap(),
        );
        app.push(make_entry(advert()).capture).unwrap();
        for (width, height) in [(96, 32), (43, 10), (25, 5), (160, 50)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            app.details = u16::MAX;
            terminal.draw(|f| draw(f, &mut app, f.area())).unwrap();
            let text: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            assert!(text.contains("Advert"));
            assert!(
                text.contains("65 72"),
                "last bytes missing at {width}x{height}"
            );
            // A second frame with no input must not move the scroll position.
            let scroll = app.details;
            terminal.draw(|f| draw(f, &mut app, f.area())).unwrap();
            assert_eq!(app.details, scroll);
        }
    }

    #[test]
    fn short_packets_show_general_payload_and_bytes_without_empty_groups() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            "Test capture".into(),
            100,
            true,
            "unused".into(),
            crate::catalogue::Catalogue::load(dir.path().join("catalogue.json")).unwrap(),
        );
        for (name, frame) in [
            ("channel", sample_frame(1)),
            ("trace", sample_frame(5)),
            ("ack", sample_frame(3)),
            ("malformed", vec![0x88, 0, 150, 0x11, 0, 1]),
            ("companion", vec![0x01, 0x02]),
        ] {
            let mut terminal = Terminal::new(TestBackend::new(160, 32)).unwrap();
            app.push(make_entry(frame).capture).unwrap();
            app.follow = true;
            terminal.draw(|f| super::super::draw(f, &mut app)).unwrap();
            let text: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            assert!(
                text.contains("GENERAL PACKET")
                    && text.contains("PAYLOAD")
                    && text.contains("WIRE BYTES")
            );
            if name == "ack" {
                assert!(text.contains("Acknowledgment"));
                assert!(!text.contains("Authentication fields"));
            }
            if name == "malformed" {
                assert!(text.contains("⚠ WARNING"));
            }
        }
    }

    #[test]
    fn full_layout_preserves_packet_selection_when_expanding_and_restoring() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            "USB / MeshCore companion".into(),
            100,
            true,
            "unused".into(),
            crate::catalogue::Catalogue::load(dir.path().join("catalogue.json")).unwrap(),
        );
        for n in 0..18 {
            app.push(make_entry(sample_frame(n)).capture).unwrap();
        }
        app.push(make_entry(advert()).capture).unwrap();
        let selected = app.selected().unwrap().id;
        for (width, height) in [(160, 44), (120, 32), (80, 32), (45, 15)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|f| super::super::draw(f, &mut app)).unwrap();
            app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                .unwrap();
            assert!(app.expand_details && app.focus_details && !app.follow);
            terminal.draw(|f| super::super::draw(f, &mut app)).unwrap();
            assert_eq!(app.selected().unwrap().id, selected);
            app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE))
                .unwrap();
            assert!(app.focus_details);
            app.push(make_entry(sample_frame(2)).capture).unwrap();
            assert_eq!(app.selected().unwrap().id, selected);
            app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
                .unwrap();
            assert!(!app.expand_details && !app.focus_details);
            terminal.draw(|f| super::super::draw(f, &mut app)).unwrap();
            assert_eq!(app.selected().unwrap().id, selected);
        }
    }
}
