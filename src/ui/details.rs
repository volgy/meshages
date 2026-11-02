//! Compact packet inspection with semantic sections and byte coloring.
use super::{ACCENT, COMPANION, MUTED, PANEL, block, packet_color};
use crate::protocol::channel::{ChannelStatus, Plaintext};
use crate::{
    app::{App, Entry},
    protocol::{AdvertSignature, Route, WireField, hex},
};
use ratatui::{prelude::*, widgets::*};

pub(super) const PAYLOAD: Color = Color::Rgb(214, 157, 245);
pub(super) const SCOPE: Color = Color::Rgb(151, 180, 255);
pub(super) const PATH: Color = Color::Rgb(110, 190, 239);
pub(super) const PLAINTEXT: Color = Color::Rgb(136, 213, 161);
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

fn label(key: &str) -> &str {
    match key {
        "Name (unverified)" => "Name",
        "Advert timestamp" | "Message timestamp" => "Timestamp",
        _ => key,
    }
}

fn wire_color(name: &str, inherited: Color) -> Color {
    match name {
        "Companion type" | "SNR" | "RSSI" => COMPANION,
        "Header" | "Route type" | "Payload type" | "Payload version" => ACCENT,
        "Transport codes" | "Code 1" | "Code 2" => SCOPE,
        "Path" | "Path length" | "Entry count" | "Entry width" => PATH,
        "Public key"
        | "Sender public key"
        | "Name (unverified)"
        | "Name"
        | "Public key prefix"
        | "Node role"
        | "Latitude"
        | "Longitude"
        | "Sender name (unverified)" => PATH,
        "Trace targets" => PATH,
        "Padding" | "Name terminator" => MUTED,
        "Trailing bytes" => Color::Yellow,
        "MAC" | "Signature" | "Auth code" => Color::Yellow,
        "Acknowledgment" => Color::Green,
        _ => inherited,
    }
}

fn signature_style(status: &AdvertSignature) -> (&'static str, Color) {
    match status {
        AdvertSignature::Valid => ("VALID SIGNATURE", Color::Green),
        AdvertSignature::Invalid => ("INVALID SIGNATURE", Color::Red),
        AdvertSignature::Unverified(_) => ("UNVERIFIED", Color::Yellow),
    }
}

/// Word wrapping that preserves literal-byte and interpretation styles, including Unicode names.
fn styled_wrap(spans: Vec<Span<'static>>, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);
    let mut lines = vec![];
    let mut line = Line::default();
    let mut used = 0;
    for span in spans {
        for word in span.content.split_whitespace() {
            let word_width = Line::from(word).width();
            if used > 0 && used + 1 + word_width > width {
                lines.push(std::mem::take(&mut line));
                used = 0;
            }
            if used > 0 {
                line.spans.push(Span::styled(" ", span.style));
                used += 1;
            }
            let word = Span::styled(word, span.style);
            for grapheme in word.styled_graphemes(Style::default()) {
                let size = Line::from(grapheme.symbol).width();
                if used > 0 && used + size > width {
                    lines.push(std::mem::take(&mut line));
                    used = 0;
                }
                line.spans
                    .push(Span::styled(grapheme.symbol.to_owned(), grapheme.style));
                used += size;
            }
        }
    }
    if !line.spans.is_empty() {
        lines.push(line);
    }
    lines
}

struct Inspector<'a> {
    entry: &'a Entry,
    bytes: &'a [u8],
    plaintext: bool,
    origin: usize,
    width: usize,
    lines: Vec<Line<'static>>,
}
impl Inspector<'_> {
    fn path_values(&self, node: &WireField) -> Option<Vec<Span<'static>>> {
        if self.plaintext {
            return None;
        }
        let raw = |range: std::ops::Range<usize>| {
            Span::styled(
                hex(self.bytes.get(range).unwrap_or_default()).replace(' ', ""),
                Style::default().fg(PATH),
            )
        };
        if node.name == "Path length" && node.children.len() == 2 {
            return Some(vec![
                raw(node.range.clone()),
                Span::styled("→", Style::default().fg(MUTED)),
                Span::styled(
                    format!(
                        "{} entries × {}",
                        node.children[0].interpretation, node.children[1].interpretation
                    ),
                    Style::default().fg(Color::White),
                ),
            ]);
        }
        let targets = node.name == "Trace targets";
        if node.name != "Path" && !targets {
            return None;
        }
        if node.children.is_empty() {
            if targets {
                return Some(vec![
                    Span::styled(
                        node.interpretation.clone(),
                        Style::default().fg(Color::White),
                    ),
                    Span::styled("· ∅", Style::default().fg(MUTED)),
                ]);
            }
            return (self.entry.decoded.hops == Some(0))
                .then(|| vec![Span::styled("∅ · empty", Style::default().fg(MUTED))]);
        }
        let mut values = vec![];
        if targets {
            values.push(Span::styled(
                node.interpretation.clone(),
                Style::default().fg(Color::White),
            ));
            values.push(Span::styled("·", Style::default().fg(MUTED)));
        }
        for (index, entry) in node.children.iter().enumerate() {
            if index > 0 {
                values.push(Span::styled("→", Style::default().fg(MUTED)));
            }
            values.push(raw(entry.range.clone()));
            if !entry.interpretation.is_empty() {
                // The compact trace still pairs each raw sample with its decoded SNR.
                let value = entry
                    .interpretation
                    .strip_suffix(" (i8 / 4)")
                    .unwrap_or(&entry.interpretation);
                values.push(Span::styled(
                    format!("({value})"),
                    Style::default().fg(Color::White),
                ));
            }
        }
        if self.entry.decoded.kind == "Trace" && !targets {
            values.push(Span::styled("· i8 / 4", Style::default().fg(MUTED)));
        }
        Some(values)
    }

    fn decrypted(&mut self, plain: &Plaintext) {
        for (index, line) in wrapped(
            &format!("DECRYPTED · {}", clean(&plain.channels.join(" / "))),
            self.width.saturating_sub(9),
        )
        .into_iter()
        .enumerate()
        {
            self.lines.push(Line::from(vec![
                Span::styled(
                    if index == 0 {
                        "      └─ "
                    } else {
                        "         "
                    },
                    Style::default().fg(MUTED),
                ),
                Span::styled(line, Style::default().fg(PLAINTEXT).bold()),
            ]));
        }
        for line in wrapped("p = plaintext offset", self.width.saturating_sub(9)) {
            self.lines.push(Line::from(Span::styled(
                format!("         {line}"),
                Style::default().fg(MUTED),
            )));
        }
        if let Some(warning) = &plain.warning {
            field(
                &mut self.lines,
                "⚠ Plaintext",
                warning,
                Color::Yellow,
                self.width,
            );
        }
        let mut parsed = Inspector {
            entry: self.entry,
            bytes: &plain.bytes,
            plaintext: true,
            origin: 0,
            width: self.width,
            lines: vec![],
        };
        for (index, node) in plain.fields.iter().enumerate() {
            parsed.node(
                node,
                "   ",
                Some(index + 1 == plain.fields.len()),
                PLAINTEXT,
            );
        }
        self.lines.extend(parsed.lines);
    }

    fn node(&mut self, node: &WireField, prefix: &str, branch: Option<bool>, inherited: Color) {
        let signature = (!self.plaintext && node.name == "Signature")
            .then_some(self.entry.decoded.advert_signature.as_ref())
            .flatten();
        let color = signature.map_or_else(
            || wire_color(&node.name, inherited),
            |status| signature_style(status).1,
        );
        let tree = match branch {
            Some(true) => "└─ ",
            Some(false) => "├─ ",
            None => "",
        };
        let offset = if node.bits.is_some() {
            "      ".to_owned()
        } else if self.plaintext {
            format!("p{:04X} ", node.range.start)
        } else {
            format!("{:04X}  ", node.range.start.saturating_sub(self.origin))
        };
        let size = if node.bits.is_some() {
            String::new()
        } else {
            format!(" · {} B", node.range.len())
        };
        let mut heading = Line::from(vec![
            Span::styled(offset, Style::default().fg(MUTED)),
            Span::styled(format!("{prefix}{tree}"), Style::default().fg(MUTED)),
            Span::styled(
                label(&node.name).to_owned(),
                Style::default().fg(color).bold(),
            ),
            Span::styled(size, Style::default().fg(MUTED)),
        ]);
        let compact_path = self.path_values(node);
        let expand = compact_path.is_none();
        let show_raw = expand
            && (node.children.is_empty() || node.children.iter().all(|child| child.bits.is_some()));
        let mut values = compact_path.unwrap_or_default();
        if let Some(bits) = &node.bits {
            if let Some(byte) = self.bytes.get(node.range.start) {
                let count = bits.end - bits.start;
                let value = (*byte >> bits.start) & ((1u16 << count) - 1) as u8;
                values.push(Span::styled(
                    format!(
                        "bits {}:{} = 0b{value:0count$b}",
                        bits.end - 1,
                        bits.start,
                        count = count as usize
                    ),
                    Style::default().fg(color),
                ));
            }
        } else if show_raw {
            let raw = self.bytes.get(node.range.clone()).unwrap_or_default();
            values.push(Span::styled(
                if raw.is_empty() {
                    "∅".into()
                } else {
                    hex(raw)
                },
                Style::default().fg(color),
            ));
        }
        if expand && !node.interpretation.is_empty() {
            if !values.is_empty() {
                values.push(Span::styled("→", Style::default().fg(MUTED)));
            }
            let issue = node.interpretation.starts_with("Truncated")
                || node.interpretation.starts_with("Missing");
            values.push(Span::styled(
                clean(&node.interpretation),
                Style::default().fg(if issue {
                    Color::Yellow
                } else if signature.is_some() {
                    color
                } else {
                    Color::White
                }),
            ));
        }
        if values.is_empty() {
            self.heading(heading);
        } else {
            // Labels can spill onto their own row; all values keep a shared column.
            let wide = self.width >= 60;
            let column = if wide { 32 } else { self.width / 3 };
            let inline = wide && heading.width() + 2 <= column;
            if inline {
                heading
                    .spans
                    .push(Span::raw(" ".repeat(column - heading.width())));
            } else {
                self.heading(std::mem::take(&mut heading));
            }
            for (index, value) in styled_wrap(values, self.width.saturating_sub(column))
                .into_iter()
                .enumerate()
            {
                let mut line = if index == 0 && inline {
                    std::mem::take(&mut heading)
                } else {
                    Line::from(" ".repeat(column))
                };
                line.spans.extend(value.spans);
                self.lines.push(line);
            }
        }
        if !self.plaintext
            && node.name == "Ciphertext"
            && let Some(channel) = &self.entry.decoded.channel
            && node.range == channel.range
            && let ChannelStatus::Decrypted(plain) = &channel.status
        {
            self.decrypted(plain);
        }
        // Catalogue matches are annotations, not additional bytes on the wire.
        let annotation = match node.name.as_str() {
            "Code 1" => Some(("Region candidates", SCOPE)),
            "Channel hash" => Some(("Channel candidates", PAYLOAD)),
            _ => None,
        };
        if !self.plaintext
            && let Some((key, color)) = annotation
            && let Some((_, value)) = self
                .entry
                .decoded
                .fields
                .iter()
                .find(|(name, _)| name == key)
        {
            let indent = format!("      {prefix}   ↳ ");
            for (index, value) in wrapped(
                &format!("Catalogue: {}", clean(value)),
                self.width
                    .saturating_sub(Line::from(indent.as_str()).width()),
            )
            .into_iter()
            .enumerate()
            {
                self.lines.push(Line::from(vec![
                    Span::styled(
                        if index == 0 {
                            indent.clone()
                        } else {
                            " ".repeat(Line::from(indent.as_str()).width())
                        },
                        Style::default().fg(MUTED),
                    ),
                    Span::styled(value, Style::default().fg(color).italic()),
                ]));
            }
        }
        if !expand {
            return;
        }
        let child_prefix = format!(
            "{prefix}{}",
            match branch {
                Some(false) => "│  ",
                Some(true) => "   ",
                None => "",
            }
        );
        for (index, child) in node.children.iter().enumerate() {
            self.node(
                child,
                &child_prefix,
                Some(index + 1 == node.children.len()),
                color,
            );
        }
    }

    fn heading(&mut self, line: Line<'static>) {
        if line.width() <= self.width {
            self.lines.push(line);
        } else {
            self.lines.extend(styled_wrap(line.spans, self.width));
        }
    }
}

fn document(entry: &Entry, show_companion: bool, width: usize) -> Vec<Line<'static>> {
    let mut inspector = Inspector {
        entry,
        bytes: &entry.capture.frame,
        plaintext: false,
        origin: if show_companion { 0 } else { 3 },
        width,
        lines: vec![],
    };
    if let Some(warning) = &entry.decoded.warning {
        field(
            &mut inspector.lines,
            "⚠ Warning",
            warning,
            Color::Yellow,
            width,
        );
    }
    section(
        &mut inspector.lines,
        "◈ GENERAL PACKET",
        "offset hex · length B",
        ACCENT,
        GENERAL_BG,
        width,
    );
    if !show_companion && (entry.decoded.snr.is_some() || entry.decoded.rssi.is_some()) {
        let metadata = ["SNR", "RSSI"]
            .iter()
            .filter_map(|key| {
                entry
                    .decoded
                    .fields
                    .iter()
                    .find(|(name, _)| name == key)
                    .map(|(name, value)| format!("{name} {value}"))
            })
            .collect::<Vec<_>>()
            .join(" · ");
        field(&mut inspector.lines, "RX metadata", &metadata, MUTED, width);
    }
    let radio = entry.capture.frame.first() == Some(&0x88);
    let mut has_payload = false;
    for node in &entry.decoded.structure {
        if !show_companion && matches!(node.name.as_str(), "Companion type" | "SNR" | "RSSI") {
            continue;
        }
        let payload = node.name == "Payload"
            || node.name == "Unparsed remainder"
            || (!radio && node.name == "Body");
        if payload {
            has_payload = true;
            inspector.lines.push(Line::from(""));
            let note = format!(
                "@{:04X} · {} B{}",
                node.range.start.saturating_sub(inspector.origin),
                node.range.len(),
                if node.name == "Unparsed remainder" {
                    " · boundary unknown"
                } else {
                    ""
                }
            );
            section(
                &mut inspector.lines,
                "▣ PAYLOAD",
                &note,
                PAYLOAD,
                PAYLOAD_BG,
                width,
            );
            if node.children.is_empty() {
                inspector.node(node, "", None, if radio { PAYLOAD } else { COMPANION });
            } else {
                for child in &node.children {
                    inspector.node(child, "", None, PAYLOAD);
                }
            }
        } else {
            inspector.node(node, "", None, if radio { ACCENT } else { COMPANION });
        }
    }
    if !has_payload {
        inspector.lines.push(Line::from(""));
        section(
            &mut inspector.lines,
            "▣ PAYLOAD",
            "Unavailable",
            PAYLOAD,
            PAYLOAD_BG,
            width,
        );
        inspector.lines.push(Line::from(Span::styled(
            "Payload boundary unavailable; inspect partial fields above.",
            Style::default().fg(MUTED).italic(),
        )));
    }
    inspector.lines.push(Line::from(""));
    byte_dump(&mut inspector.lines, entry, show_companion, width);
    inspector.lines
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
        if let Some(status) = &d.advert_signature {
            let (badge, color) = signature_style(status);
            badges.push(Span::styled(
                format!("  {badge}"),
                Style::default().fg(color).bold(),
            ));
        } else if d
            .channel
            .as_ref()
            .is_some_and(|channel| matches!(channel.status, ChannelStatus::Decrypted(_)))
        {
            badges.push(Span::styled(
                "  DECRYPTED",
                Style::default().fg(PLAINTEXT).bold(),
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

    fn new_payload_frames() -> Vec<Vec<u8>> {
        let mut frames: Vec<_> = crate::protocol::advert_vectors::all()
            .iter()
            .map(|v| crate::protocol::advert_vectors::frame(&v.name))
            .collect();
        for (ty, payload) in [
            (11, vec![0x81, 0x1e, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0x80]),
            (
                11,
                vec![0x92, 0xdc, 0x98, 0xba, 0xdc, 0xfe, 1, 2, 3, 4, 5, 6, 7, 8],
            ),
            (11, vec![0x31, 0xde, 0xad]),
            (
                9,
                vec![
                    0x98, 0xba, 0xdc, 0xfe, 0xff, 0xff, 0xff, 0xff, 1, 0xaa, 0xbb, 0xcc, 0xdd,
                ],
            ),
            (9, vec![0; 9]),
            (9, vec![0, 0, 0, 0, 0, 0, 0, 0, 1, 0xaa]),
            (10, vec![0x13, 0x98, 0xba, 0xdc, 0xfe]),
            (10, vec![0x12, 0xde, 0xad]),
        ] {
            let mut frame = vec![0x88, 0xf8, 0xa0, (ty << 2) | 2, 0];
            frame.extend(payload);
            frames.push(frame);
        }
        frames
    }

    #[test]
    fn advert_badges_and_signature_fields_use_typed_verification_status_and_colors() {
        let valid = crate::protocol::advert_vectors::frame("public_cougar");
        let mut invalid = valid.clone();
        invalid[41] ^= 1;
        let incomplete = valid[..60].to_vec();
        let mut unsupported = valid.clone();
        unsupported[3] |= 0x40;
        for (frame, badge, color) in [
            (valid, "VALID SIGNATURE", Color::Green),
            (invalid, "INVALID SIGNATURE", Color::Red),
            (incomplete, "UNVERIFIED", Color::Yellow),
            (unsupported, "UNVERIFIED", Color::Yellow),
            (
                crate::protocol::advert_vectors::frame("oversized_application"),
                "UNVERIFIED",
                Color::Yellow,
            ),
        ] {
            for show_companion in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let catalogue =
                    crate::catalogue::Catalogue::load(dir.path().join("catalogue.json")).unwrap();
                let mut app = App::new(
                    "Test".into(),
                    100,
                    show_companion,
                    "unused".into(),
                    catalogue,
                );
                app.push(make_entry(frame.clone()).capture).unwrap();
                for (width, height) in [(160, 60), (80, 40), (45, 15)] {
                    app.expand_details = true;
                    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                    terminal.draw(|f| super::super::draw(f, &mut app)).unwrap();
                    let buffer = terminal.backend().buffer();
                    let text: String = buffer.content.iter().map(|cell| cell.symbol()).collect();
                    assert!(text.contains(badge), "missing {badge} at {width}");
                    for y in 0..height {
                        let row: String = (0..width).map(|x| buffer[(x, y)].symbol()).collect();
                        if let Some(start) = row.find(badge) {
                            let x = Line::from(&row[..start]).width() as u16;
                            assert_eq!(buffer[(x, y)].fg, color);
                        }
                    }
                }
                let entry = make_entry(frame.clone());
                let lines = document(&entry, show_companion, 76);
                let label = lines
                    .iter()
                    .flat_map(|line| &line.spans)
                    .find(|span| span.content == "Signature");
                if let Some(label) = label {
                    assert_eq!(label.style.fg, Some(color));
                }
                if badge == "VALID SIGNATURE" {
                    let text = lines
                        .iter()
                        .map(Line::to_string)
                        .collect::<Vec<_>>()
                        .join(" ");
                    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
                    assert!(text.contains("identity not established"));
                    assert!(!text.contains("unverified"));
                }
            }
        }
    }

    #[test]
    fn new_payloads_render_at_narrow_and_wide_sizes_without_changing_the_dump() {
        for frame in new_payload_frames() {
            let entry = make_entry(frame.clone());
            for show_companion in [false, true] {
                for width in [25, 43, 76, 118] {
                    let lines = document(&entry, show_companion, width);
                    let dump_start = lines
                        .iter()
                        .position(|line| line.to_string().contains("BYTES /"))
                        .unwrap();
                    let mut expected = vec![];
                    byte_dump(&mut expected, &entry, show_companion, width);
                    assert_eq!(&lines[dump_start..], expected);
                    for line in &lines[..dump_start] {
                        assert!(
                            line.width() <= width,
                            "line exceeds {width}: {:?}",
                            line.to_string()
                        );
                    }
                    assert_eq!(entry.capture.frame, frame);
                }
            }
        }
    }

    #[test]
    fn decrypted_fields_use_plaintext_offsets_after_ciphertext_and_preserve_the_full_dump() {
        use crate::protocol::channel::test_vectors::{bytes, frame, get};
        for name in [
            "public_text",
            "unicode_text",
            "binary_datagram",
            "unsupported_text",
            "bad_datagram_length",
            "invalid_utf8",
        ] {
            let vector = get(name);
            let dir = tempfile::tempdir().unwrap();
            let mut catalogue =
                crate::catalogue::Catalogue::load(dir.path().join("catalogue.json")).unwrap();
            if name != "public_text" {
                catalogue
                    .add(crate::catalogue::Category::Channel, "Fixture", &vector.key)
                    .unwrap();
            }
            let mut entry = make_entry(frame(&vector));
            let wire = entry.capture.frame.clone();
            catalogue.annotate(&mut entry.decoded);
            for show_companion in [false, true] {
                for width in [25, 43, 76, 118] {
                    let lines = document(&entry, show_companion, width);
                    let text = lines
                        .iter()
                        .map(Line::to_string)
                        .collect::<Vec<_>>()
                        .join("\n");
                    assert!(text.find("Ciphertext").unwrap() < text.find("DECRYPTED").unwrap());
                    assert!(text.find("DECRYPTED").unwrap() < text.find("p0000").unwrap());
                    assert!(text.find("p0000").unwrap() < text.find("BYTES /").unwrap());
                    let normalized: String = text.split_whitespace().collect();
                    assert!(normalized.contains("p=plaintextoffset"));
                    if name == "public_text" {
                        assert!(
                            text.contains("Alice")
                                && normalized.contains("hellomesh")
                                && normalized.contains("Sendername(unverified)")
                        );
                        let sender_bytes = "41 6C 69 63 65";
                        let mac_bytes = hex(&bytes(&vector.mac));
                        let sender = lines
                            .iter()
                            .map(Line::to_string)
                            .find(|line| line.contains(sender_bytes))
                            .unwrap();
                        let mac = lines
                            .iter()
                            .map(Line::to_string)
                            .find(|line| line.contains(&mac_bytes))
                            .unwrap();
                        let value_column = |line: &str, value: &str| {
                            Line::from(&line[..line.find(value).unwrap()]).width()
                        };
                        assert_eq!(
                            value_column(&sender, sender_bytes),
                            value_column(&mac, &mac_bytes),
                            "sender and MAC values must align at width {width}"
                        );
                        if let Some(continuation) = lines
                            .iter()
                            .map(Line::to_string)
                            .find(|line| line.trim() == "Alice")
                        {
                            assert_eq!(
                                value_column(&continuation, "Alice"),
                                value_column(&mac, &mac_bytes)
                            );
                        }
                    }
                    if name == "binary_datagram" {
                        assert!(normalized.contains("006100FF00") && text.contains("p0003"));
                    }
                    let start = lines
                        .iter()
                        .position(|line| line.to_string().contains("BYTES /"))
                        .unwrap();
                    let mut expected = vec![];
                    byte_dump(&mut expected, &entry, show_companion, width);
                    assert_eq!(&lines[start..], expected);
                    assert_eq!(entry.capture.frame, wire);
                }
            }
        }
    }

    #[test]
    fn decrypted_packet_badge_and_plaintext_views_render_at_wide_and_minimum_sizes() {
        use crate::protocol::channel::test_vectors::{frame, get};
        for name in ["public_text", "binary_datagram", "bad_datagram_length"] {
            let vector = get(name);
            let dir = tempfile::tempdir().unwrap();
            let mut catalogue =
                crate::catalogue::Catalogue::load(dir.path().join("catalogue.json")).unwrap();
            if name != "public_text" {
                catalogue
                    .add(crate::catalogue::Category::Channel, "Fixture", &vector.key)
                    .unwrap();
            }
            let mut app = App::new(
                "Test capture".into(),
                100,
                false,
                "unused".into(),
                catalogue,
            );
            app.push(make_entry(frame(&vector)).capture).unwrap();
            for (width, height) in [(160, 60), (120, 40), (80, 40), (45, 15)] {
                let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                for expanded in [false, true] {
                    app.expand_details = expanded;
                    app.details = 0;
                    terminal.draw(|f| super::super::draw(f, &mut app)).unwrap();
                    let text: String = terminal
                        .backend()
                        .buffer()
                        .content
                        .iter()
                        .map(|cell| cell.symbol())
                        .collect();
                    assert!(text.contains("DECRYPTED"));
                    assert!(!text.contains("ENCRYPTED"));
                    app.details = u16::MAX;
                    terminal.draw(|f| super::super::draw(f, &mut app)).unwrap();
                    let text: String = terminal
                        .backend()
                        .buffer()
                        .content
                        .iter()
                        .map(|cell| cell.symbol())
                        .collect();
                    assert!(text.contains("DECRYPTED"));
                }
            }
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
    fn sections_preserve_wire_order_raw_fields_and_interpretations_at_different_widths() {
        let normalized = |s: &str| s.split_whitespace().collect::<String>();
        fn check(node: &WireField, entry: &Entry, text: &str) {
            let normalized = |s: &str| s.split_whitespace().collect::<String>();
            if node.name == "Path" && entry.decoded.hops == Some(0) {
                assert!(text.contains("∅·empty"));
                return;
            }
            if node.name == "Path" && !node.children.is_empty() {
                for child in &node.children {
                    let bytes = hex(&entry.capture.frame[child.range.clone()]);
                    assert!(text.contains(&normalized(&bytes)));
                    let value = child
                        .interpretation
                        .strip_suffix(" (i8 / 4)")
                        .unwrap_or(&child.interpretation);
                    assert!(text.contains(&normalized(value)));
                }
                return;
            }
            assert!(
                text.contains(&normalized(&clean(&node.interpretation))),
                "lost interpretation {}",
                node.interpretation
            );
            if node.bits.is_none()
                && (node.children.is_empty()
                    || node.children.iter().all(|child| child.bits.is_some()))
            {
                assert!(
                    text.contains(&normalized(&hex(&entry.capture.frame[node.range.clone()]))),
                    "lost bytes for {}",
                    node.name
                );
            }
            for child in &node.children {
                check(child, entry, text);
            }
        }
        let mut frames: Vec<_> = (0..6).map(sample_frame).collect();
        frames.extend(new_payload_frames());
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
                    let parsed = normalized(text.split("⌗").next().unwrap());
                    for node in &entry.decoded.structure {
                        if show_companion
                            || !matches!(node.name.as_str(), "Companion type" | "SNR" | "RSSI")
                        {
                            check(node, &entry, &parsed);
                        }
                    }
                    // Advert interpretation must follow its bytes, including long signatures.
                    if text.contains("Hilltop") {
                        let name = text.find("Hilltop").unwrap();
                        let signature = text.find("Signature").unwrap();
                        let key = text.find("Public key").unwrap();
                        let timestamp = text.find("Timestamp").unwrap();
                        let app = text.find("Application data").unwrap();
                        assert!(
                            payload < key
                                && key < timestamp
                                && timestamp < signature
                                && signature < app
                                && app < name
                        );
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
    fn scalar_bytes_interpretation_and_offsets_match_the_dump_origin() {
        let entry = make_entry(vec![0x88, 0x10, 0xa1, 0x0d, 0, 1, 2, 3, 4]);
        for show_companion in [false, true] {
            let lines = document(&entry, show_companion, 118);
            let ack = lines
                .iter()
                .map(Line::to_string)
                .find(|line| line.contains("Acknowledgment"))
                .unwrap();
            assert!(ack.starts_with(if show_companion { "0005" } else { "0002" }));
            assert!(ack.contains("01 02 03 04 → 0x04030201 (u32 LE)"));
            let header = lines
                .iter()
                .map(Line::to_string)
                .find(|line| line.contains("Header ·"))
                .unwrap();
            assert!(header.starts_with(if show_companion { "0003" } else { "0000" }));
        }
    }

    #[test]
    fn compact_paths_keep_hash_boundaries_offsets_and_samples_when_wrapping() {
        for (width, groups) in [
            (1, ["A1", "B2"]),
            (2, ["A1B2", "C3D4"]),
            (3, ["A1B2C3", "D4E5F6"]),
        ] {
            let encoded = ((width as u8 - 1) << 6) | 2;
            let mut frame = vec![0x88, 0, 150, 0x0d, encoded];
            frame.extend_from_slice(&[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6][..2 * width]);
            frame.extend_from_slice(&[1, 2, 3, 4]);
            let entry = make_entry(frame);
            for show_companion in [false, true] {
                for columns in [25, 43, 70, 118] {
                    let lines: Vec<_> = document(&entry, show_companion, columns)
                        .iter()
                        .map(Line::to_string)
                        .collect();
                    let text = lines.join("\n");
                    assert!(
                        !text.contains("Hash 1")
                            && !text.contains("Entry count")
                            && !text.contains("Entry width")
                    );
                    for group in groups {
                        // A multi-byte hash must stay together on one line, even in narrow panes.
                        assert!(
                            lines
                                .iter()
                                .any(|line| line.split_whitespace().any(|word| word == group))
                        );
                    }
                    let path = lines.iter().find(|line| line.contains("Path ·")).unwrap();
                    assert!(path.starts_with(if show_companion { "0005" } else { "0002" }));
                    if columns == 118 {
                        assert!(path.contains(&format!("{} → {}", groups[0], groups[1])));
                        let length = lines
                            .iter()
                            .find(|line| line.contains("Path length"))
                            .unwrap();
                        assert!(length.contains(&format!("{encoded:02X} → 2 entries × {width} B")));
                    }
                }
            }
        }
        let trace = make_entry(vec![
            0x88, 0, 150, 0x25, 2, 4, 0xf8, 1, 2, 3, 4, 0, 0, 0, 0, 0,
        ]);
        let lines: Vec<_> = document(&trace, false, 118)
            .iter()
            .map(Line::to_string)
            .collect();
        let path = lines.iter().find(|line| line.contains("Path ·")).unwrap();
        assert!(path.contains("04 (+1.00 dB) → F8 (-2.00 dB) · i8 / 4"));
        assert!(!lines.iter().any(|line| line.contains("SNR sample")));
    }

    #[test]
    fn empty_paths_are_explicit_and_truncated_paths_keep_partial_bytes_and_warning() {
        let empty = make_entry(vec![0x88, 0, 150, 0x0d, 0, 1, 2, 3, 4]);
        let lines: Vec<_> = document(&empty, false, 118)
            .iter()
            .map(Line::to_string)
            .collect();
        let path = lines.iter().find(|line| line.contains("Path ·")).unwrap();
        assert!(path.contains("0 B") && path.contains("∅ · empty"));
        let partial = make_entry(vec![0x88, 0, 150, 0x0d, 0x42, 0xa1, 0xb2, 0xc3]);
        let lines: Vec<_> = document(&partial, false, 118)
            .iter()
            .map(Line::to_string)
            .collect();
        let path = lines.iter().find(|line| line.contains("Path ·")).unwrap();
        assert!(path.contains("A1 B2 C3 → Truncated: expected 4 B, got 3 B"));
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
            false,
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
