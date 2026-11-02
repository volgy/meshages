use crate::app::{App, Page};
use ratatui::{prelude::*, widgets::*};
mod details;
const BG: Color = Color::Rgb(15, 20, 30);
const PANEL: Color = Color::Rgb(22, 29, 41);
const MUTED: Color = Color::Rgb(135, 151, 173);
const COMPANION: Color = Color::Rgb(116, 124, 141);
const ACCENT: Color = Color::Rgb(89, 220, 196);
fn block(title: impl Into<Line<'static>>, active: bool) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .title(title)
        .border_style(Style::default().fg(if active {
            ACCENT
        } else {
            Color::Rgb(59, 77, 98)
        }))
        .style(Style::default().bg(PANEL))
}
fn kind_color(kind: &str) -> Color {
    match kind {
        "Advert" => Color::Cyan,
        "ACK" => Color::Green,
        "Channel text" | "Channel data" => Color::Magenta,
        "Direct text" => Color::Yellow,
        "Malformed RX" => Color::Red,
        _ => Color::Blue,
    }
}
fn packet_color(entry: &crate::app::Entry) -> Color {
    if entry.capture.frame.first() == Some(&0x88) {
        kind_color(&entry.decoded.kind)
    } else {
        COMPANION
    }
}
fn packet_row(entry: &crate::app::Entry) -> Row<'static> {
    let d = &entry.decoded;
    let summary = if entry.capture.frame.first() == Some(&0x88) {
        d.radio_summary()
    } else {
        d.summary.clone()
    };
    Row::new(vec![
        Cell::from(Text::from(vec![
            Line::from(entry.capture.at.format("%H:%M:%S").to_string()),
            Line::from(format!("#{:05}", entry.id)),
        ]))
        .style(Style::default().fg(MUTED)),
        Cell::from(Text::from(vec![
            Line::from(Span::styled(
                format!("{}{}", d.kind, if d.warning.is_some() { " ⚠" } else { "" }),
                Style::default().fg(packet_color(entry)).bold(),
            )),
            Line::from(Span::styled(summary, Style::default().fg(MUTED))),
        ])),
        Cell::from(Text::from(vec![
            Line::from(d.rssi.map_or("—".into(), |v| v.to_string())),
            Line::from(Span::styled(
                d.snr.map_or("—".into(), |v| format!("{v:+.1}")),
                Style::default().fg(MUTED),
            )),
        ])),
        Cell::from(Text::from(vec![
            Line::from(d.hops.map_or("—".into(), |v| v.to_string())),
            Line::from(Span::styled(
                d.path_width.map_or("—".into(), |v| format!("{v} B")),
                Style::default().fg(MUTED),
            )),
        ])),
    ])
    .height(2)
}
pub fn draw(f: &mut Frame, app: &mut App) {
    f.render_widget(
        Block::default().style(Style::default().bg(BG).fg(Color::White)),
        f.area(),
    );
    if f.area().width < 45 || f.area().height < 15 {
        f.render_widget(
            Paragraph::new(
                "meshages\n\nPlease resize to at least 45 × 15.\nCapture continues.  q quit",
            )
            .centered(),
            f.area(),
        );
        return;
    }
    if app.page != Page::Packets {
        catalogue(f, app);
        return;
    }
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(1),
        Constraint::Length(2),
    ])
    .split(f.area());
    let mode = if app.follow {
        "● FOLLOW"
    } else {
        "○ INSPECT"
    };
    let title = Line::from(vec![
        Span::styled(" ◈ meshages ", Style::default().fg(ACCENT).bold()),
        Span::styled("/ MeshCore packet inspector", Style::default().fg(MUTED)),
        Span::styled(
            format!(
                "   {mode}   {} received · {} retained",
                app.total,
                app.entries.len()
            ),
            Style::default().fg(ACCENT),
        ),
    ]);
    f.render_widget(
        Paragraph::new(title).block(block(format!(" {} ", app.source), false)),
        rows[0],
    );
    let panes = if app.expand_details {
        Layout::horizontal([Constraint::Length(0), Constraint::Min(1)]).split(rows[1])
    } else if rows[1].width >= 110 {
        let list_width = (rows[1].width * 2 / 5).clamp(45, 66);
        Layout::horizontal([Constraint::Length(list_width), Constraint::Min(1)]).split(rows[1])
    } else {
        Layout::vertical([Constraint::Percentage(42), Constraint::Percentage(58)]).split(rows[1])
    };
    let items = app.visible.iter().map(|&i| packet_row(&app.entries[i]));
    let mut table = Table::new(
        items,
        [
            Constraint::Length(8),
            Constraint::Min(12),
            Constraint::Length(5),
            Constraint::Length(4),
        ],
    )
    .block(block(
        format!(" 01 / Incoming · {} shown ", app.visible.len()),
        !app.focus_details,
    ))
    .row_highlight_style(Style::default().bg(Color::Rgb(38, 62, 75)).bold())
    .highlight_symbol("▌ ");
    if panes[0].height >= 5 {
        table = table.header(
            Row::new(["TIME", "TYPE / ROUTE · B", "RX¹", "PATH"])
                .style(Style::default().fg(MUTED))
                .bottom_margin(u16::from(panes[0].height >= 8)),
        );
    }
    if !app.expand_details {
        f.render_stateful_widget(table, panes[0], &mut app.table);
    }
    if !app.expand_details && app.visible.is_empty() {
        let inner = panes[0].inner(Margin::new(3, 4));
        f.render_widget(
            Paragraph::new(if app.filter.is_empty() {
                "Listening for raw radio packets…\n\nNo traffic yet. Press ? for help."
            } else {
                "No packets match this filter.\nEsc clears the filter."
            })
            .style(Style::default().fg(MUTED))
            .wrap(Wrap { trim: false }),
            inner,
        );
    }
    details::draw(f, app, panes[1]);
    let query = if app.filter.is_empty() {
        "all packets"
    } else {
        &app.filter
    };
    f.render_widget(
        Paragraph::new(format!(
            " / {query}{}   · {} evicted · {}",
            if app.editing { "▌" } else { "" },
            app.evicted,
            app.status
        ))
        .style(Style::default().fg(if app.editing { ACCENT } else { MUTED })),
        rows[2],
    );
    let detail_action = if app.expand_details {
        "restore"
    } else {
        "expand"
    };
    let footer = if f.area().width < 85 {
        format!(
            " ↑↓ move  Tab focus  Enter {detail_action}\n / filter  Space follow  ? help  q quit"
        )
    } else {
        format!(
            " ↑↓ select / scroll  Tab focus  Enter {detail_action} details  / filter  ? help\n Space follow  e export  r regions  c channels  Esc back  q quit"
        )
    };
    f.render_widget(
        Paragraph::new(footer).style(Style::default().fg(MUTED)),
        rows[3],
    );
    if app.help {
        help(f, app.help_colors);
    }
}
fn catalogue(f: &mut Frame, app: &mut App) {
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(6),
        Constraint::Length(1),
        Constraint::Length(2),
    ])
    .split(f.area());
    let tabs = [
        (Page::Packets, " 1 Packets "),
        (Page::Regions, " 2 Regions "),
        (Page::Channels, " 3 Channels "),
    ];
    let mut nav = vec![Span::styled(
        " ◈ meshages   ",
        Style::default().fg(ACCENT).bold(),
    )];
    for (page, label) in tabs {
        nav.push(Span::styled(
            label,
            if app.page == page {
                Style::default().fg(BG).bg(ACCENT).bold()
            } else {
                Style::default().fg(MUTED)
            },
        ));
    }
    f.render_widget(
        Paragraph::new(Line::from(nav)).block(block(
            format!(" Local catalogue · {} packets received ", app.total),
            false,
        )),
        rows[0],
    );
    let panes = if rows[1].width >= 100 {
        Layout::horizontal([Constraint::Percentage(52), Constraint::Percentage(48)]).split(rows[1])
    } else {
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).split(rows[1])
    };
    let regions = app.page == Page::Regions;
    let entries = if regions {
        app.catalogue.regions()
    } else {
        app.catalogue.channels()
    };
    let items = entries.iter().map(|entry| {
        Row::new(vec![
            Cell::from(format!(
                "{}{}{}",
                if entry.device_default { "★ " } else { "" },
                entry.value.name,
                if entry.conflict {
                    " ⚠"
                } else if entry.alias {
                    " ↔"
                } else {
                    ""
                }
            ))
            .style(
                Style::default()
                    .fg(if entry.conflict {
                        Color::Yellow
                    } else if regions {
                        ACCENT
                    } else {
                        Color::Magenta
                    })
                    .bold(),
            ),
            Cell::from(entry.source()),
            Cell::from(entry.value.fingerprint()).style(Style::default().fg(MUTED)),
        ])
    });
    let table = Table::new(
        items,
        [
            Constraint::Min(10),
            Constraint::Length(18),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(["NAME", "SOURCE", "KEY"])
            .style(Style::default().fg(MUTED))
            .bottom_margin(1),
    )
    .block(block(
        format!(
            " {} · {} entries ",
            if regions { "Regions" } else { "Channels" },
            entries.len()
        ),
        true,
    ))
    .row_highlight_style(Style::default().bg(Color::Rgb(38, 62, 75)).bold())
    .highlight_symbol("▌ ");
    let state = if regions {
        &mut app.regions_table
    } else {
        &mut app.channels_table
    };
    f.render_stateful_widget(table, panes[0], state);
    if entries.is_empty() {
        f.render_widget(
            Paragraph::new(if regions {
                "No regions yet.\nPress a to add a region by name."
            } else {
                "No channels yet.\nPress a to add a channel, or connect a companion."
            })
            .style(Style::default().fg(MUTED))
            .wrap(Wrap { trim: false }),
            panes[0].inner(Margin::new(2, 3)),
        );
    }
    let mut lines = vec![];
    let noun = if regions { "region" } else { "channel" };
    if let Some(entry) = app.catalogue_selected(app.page) {
        lines.push(Line::from(Span::styled(
            entry.value.name.clone(),
            Style::default()
                .fg(if regions { ACCENT } else { Color::Magenta })
                .bold(),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Source: {}", entry.source())));
        if entry.conflict {
            lines.push(Line::from(Span::styled(
                "⚠ Same name, different keys. Both entries are kept.",
                Style::default().fg(Color::Yellow),
            )));
        }
        if entry.alias {
            lines.push(Line::from("↔ Another name uses this same key (an alias)."));
        }
        if entry.device_default {
            lines.push(Line::from(Span::styled(
                "★ Current companion's default region",
                Style::default().fg(ACCENT),
            )));
            lines.push(Line::from(""));
        }
        if !entry.device_slots.is_empty() {
            lines.push(Line::from(format!(
                "Device slots: {}",
                entry
                    .device_slots
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        lines.push(Line::from(format!(
            "Key fingerprint: {}",
            entry.value.fingerprint()
        )));
        if entry.conflict {
            lines.push(Line::from(format!("Full key: {}", entry.value.key)));
        }
        if !regions {
            lines.push(Line::from(format!(
                "Channel hash: {:02X}",
                entry.value.channel_hash()
            )));
        }
        lines.push(Line::from(""));
        let (title, explanation) = match (entry.built_in, entry.manual, entry.device()) {
            (true, _, device) => (
                if device {
                    "Built-in + device channel"
                } else {
                    "Built-in channel"
                }
                .into(),
                format!(
                    "The standard Public channel is always available locally. It stays in memory, is not saved in the catalogue, and cannot be deleted.{}",
                    if device {
                        " It is also configured on the connected companion."
                    } else {
                        ""
                    }
                ),
            ),
            (false, true, true) => (
                format!("Manual + device {noun}"),
                format!(
                    "This {noun} is saved in your catalogue and provided by the connected companion. Delete removes only the manual copy; the device entry stays visible."
                ),
            ),
            (false, true, false) => (
                format!("Manual {noun}"),
                format!(
                    "This {noun} is saved in your local catalogue. Delete removes it from the catalogue."
                ),
            ),
            _ => (
                format!("Device {noun}"),
                format!(
                    "This {noun} is provided by the connected companion. It stays in memory, is read-only, and is not saved in your catalogue."
                ),
            ),
        };
        lines.push(Line::from(Span::styled(
            title,
            Style::default()
                .fg(if regions { ACCENT } else { Color::Magenta })
                .bold(),
        )));
        lines.push(Line::from(explanation));
    } else {
        lines.push(Line::from(Span::styled(
            format!("About {}", if regions { "regions" } else { "channels" }),
            Style::default()
                .fg(if regions { ACCENT } else { Color::Magenta })
                .bold(),
        )));
        lines.push(Line::from(if regions {
            "Add region names manually with a; keys are derived automatically. The companion's default region appears as a read-only entry."
        } else {
            "Public is always available as a read-only built-in. Add other channels with a; the companion's configured channels also appear automatically."
        }));
    }
    lines.push(Line::from(""));
    if regions {
        lines.push(Line::from(
            "Packet region candidates use 16-bit transport codes; collisions are possible.",
        ));
    } else {
        lines.push(Line::from("Packet channel candidates use an 8-bit hash. Matching a hash does not verify or decrypt the content."));
    }
    if app
        .catalogue_selected(app.page)
        .is_none_or(|entry| entry.manual)
    {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("File: {}", app.catalogue.path.display()),
            Style::default().fg(MUTED),
        )));
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block(" About this entry ", false)),
        panes[1],
    );
    f.render_widget(
        Paragraph::new(format!(" {}", app.status)).style(Style::default().fg(MUTED)),
        rows[2],
    );
    let remove = match app.catalogue_selected(app.page) {
        Some(e) if e.built_in => "built-in entry read-only",
        Some(e) if e.manual && e.device() => "d remove manual copy",
        Some(e) if e.manual => "d / Delete remove",
        Some(_) => "device entry read-only",
        None => "d remove manual entry",
    };
    let footer = format!(
        " ↑↓ select  a add {}  {remove}  Tab {}\n 1 / Esc packets  r regions  c channels  ? help  q quit",
        if regions { "region" } else { "channel" },
        if regions { "channels" } else { "regions" }
    );
    f.render_widget(
        Paragraph::new(footer).style(Style::default().fg(MUTED)),
        rows[3],
    );
    if let Some(form) = &app.catalogue_form {
        let region = form.category == crate::catalogue::Category::Region;
        let area = centered(f.area(), 78, if region { 12 } else { 16 });
        f.render_widget(Clear, area);
        f.render_widget(
            block(format!(" + / Add manual {} ", form.category.label()), true),
            area,
        );
        let constraints = if region {
            vec![
                Constraint::Length(3),
                Constraint::Min(2),
                Constraint::Length(2),
            ]
        } else {
            vec![
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(2),
                Constraint::Length(2),
            ]
        };
        let fields = Layout::vertical(constraints).split(area.inner(Margin::new(1, 1)));
        let mut inputs = vec![(
            if region {
                " Region name "
            } else {
                " Name · #hashtag / custom "
            },
            &form.name,
            !form.focus_key,
        )];
        if !region {
            inputs.push((" Key · 32 hex digits, or blank ", &form.key, form.focus_key));
        }
        for (index, (label, value, active)) in inputs.into_iter().enumerate() {
            let text = format!("{value}{}", if active { "▌" } else { "" });
            let offset = Line::from(text.as_str())
                .width()
                .saturating_sub(fields[index].width.saturating_sub(3) as usize)
                .min(u16::MAX as usize) as u16;
            f.render_widget(
                Paragraph::new(text)
                    .scroll((0, offset))
                    .block(block(label, active)),
                fields[index],
            );
        }
        let hint = if form.error.is_empty() && region {
            "Enter a region name. Names are case-sensitive; the key is derived automatically."
        } else if form.error.is_empty() {
            "Blank key: derive from #name. Other names need a 32-digit hex key. Public is already available as a built-in."
        } else {
            &form.error
        };
        f.render_widget(
            Paragraph::new(hint)
                .wrap(Wrap { trim: false })
                .style(Style::default().fg(if form.error.is_empty() {
                    MUTED
                } else {
                    Color::Yellow
                })),
            fields[fields.len() - 2],
        );
        f.render_widget(
            Paragraph::new(if region {
                "Enter save · Esc cancel"
            } else {
                "Tab switch field · Enter save · Esc cancel"
            })
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(ACCENT)),
            fields[fields.len() - 1],
        );
    }
    if app.help {
        help(f, app.help_colors);
    }
}
fn help(f: &mut Frame, colors: bool) {
    if colors {
        color_help(f);
        return;
    }
    let area = centered(f.area(), 78, 39);
    f.render_widget(Clear, area);
    let text = vec![
        Line::from(Span::styled(
            "Navigate the mesh",
            Style::default().fg(ACCENT).bold(),
        )),
        Line::from(""),
        Line::from("↑ / ↓  j / k      Select packet / scroll focused details"),
        Line::from("Tab              Switch focus between panels"),
        Line::from("Enter            Expand / restore details (pauses follow)"),
        Line::from("PageUp / PageDown Move ten rows / scroll details"),
        Line::from("Home / g         Oldest visible packet"),
        Line::from("End / G / f      Jump to latest and follow"),
        Line::from("Space            Toggle follow (capture always continues)"),
        Line::from("/                Search types, fields, hashes, wire hex"),
        Line::from("Enter in search  Apply search"),
        Line::from("Esc              Restore panels / clear search / connections"),
        Line::from("e                Append visible packets to JSONL export"),
        Line::from("r / 2   c / 3    Open regions / channels (1 returns to packets)"),
        Line::from("a   d / Delete   Add / remove manual regions or channels"),
        Line::from("Tab / Esc        Switch catalogue tab / return to packets"),
        Line::from("? / F1           Open / close help"),
        Line::from("Tab / ← / →      Switch help between keys and colors"),
        Line::from("q / Ctrl+C       Quit"),
        Line::from(""),
        Line::from(Span::styled(
            "What am I seeing?",
            Style::default().fg(ACCENT).bold(),
        )),
        Line::from("Raw RX packets include radio signal, route, path and payload."),
        Line::from("RX¹ shows RSSI (dBm), then SNR (dB) on the second line."),
        Line::from("PATH shows entry count, then encoded bytes per entry."),
        Line::from("Every RX row shows route and mesh bytes on its second line."),
        Line::from("Details follow wire order: hex offset, byte length, bytes → value."),
        Line::from("Path entries are hashes, not unique node identities. Direct"),
        Line::from("routes show remaining path; trace paths contain SNR samples."),
        Line::from("Encrypted content needs keys; advertisements are unverified."),
        Line::from(""),
        Line::from("Retention is bounded. --record saves frames before eviction."),
        Line::from("Default details show radio bytes; --show-companion shows companion"),
        Line::from("fields, responses/pushes, and complete companion-frame bytes."),
        Line::from("Catalogue changes are local. No radio discovery is performed."),
    ];
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block(" ? / Keys · Tab colors · Esc close ", true)),
        area,
    );
}
fn color_help(f: &mut Frame) {
    let area = centered(f.area(), 78, 27);
    f.render_widget(Clear, area);
    let parts = Layout::vertical([Constraint::Min(1), Constraint::Length(3)])
        .split(area.inner(Margin::new(1, 1)));
    f.render_widget(block(" ? / Colors · Tab keys · Esc close ", true), area);
    let mut rows: Vec<_> = [
        ("Advert", kind_color("Advert")),
        ("ACK", kind_color("ACK")),
        ("Channel text / data", kind_color("Channel text")),
        ("Direct text / detail warnings", kind_color("Direct text")),
        ("Malformed RX", kind_color("Malformed RX")),
        ("Other radio packet types", kind_color("Request")),
        ("Companion frames (--show-companion)", COMPANION),
        ("Packet sections / focused borders / follow", ACCENT),
        ("Time / ID / route / secondary values", MUTED),
        (
            "Payload sections / content / payload bytes",
            details::PAYLOAD,
        ),
        ("Path / identity values / path bytes", details::PATH),
        (
            "Scope codes / region candidates / scope bytes",
            details::SCOPE,
        ),
        (
            "Authentication fields (not a verification result)",
            Color::Yellow,
        ),
    ]
    .into_iter()
    .map(|(label, color)| {
        Row::new(vec![
            Cell::from("■").style(Style::default().fg(color)),
            Cell::from(label),
        ])
    })
    .collect();
    rows.insert(
        7,
        Row::new(vec![Cell::from("▌"), Cell::from("Selected row")])
            .style(Style::default().bg(Color::Rgb(38, 62, 75)).bold()),
    );
    f.render_widget(
        Table::new(rows, [Constraint::Length(2), Constraint::Min(1)]),
        parts[0],
    );
    f.render_widget(
        Paragraph::new("Type colors are not signal or verification.\n⚠ marks a warning.")
            .style(Style::default().fg(MUTED))
            .wrap(Wrap { trim: false }),
        parts[1],
    );
}
pub fn centered(area: Rect, width: u16, height: u16) -> Rect {
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width.min(area.width),
        height.min(area.height),
    )
}
pub fn picker(
    f: &mut Frame,
    options: &[String],
    selected: usize,
    status: &str,
    show_all_ble: bool,
) {
    f.render_widget(
        Block::default().style(Style::default().bg(BG).fg(Color::White)),
        f.area(),
    );
    let area = centered(f.area(), 88, 24);
    let rows = Layout::vertical([
        Constraint::Length(5),
        Constraint::Min(4),
        Constraint::Length(6),
    ])
    .split(area);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "◈ meshages",
                Style::default().fg(ACCENT).bold(),
            )),
            Line::from("A closer look at your mesh."),
            Line::from(""),
            Line::from("Choose a companion · devices update automatically"),
        ]),
        rows[0],
    );
    let items = options.iter().map(|s| ListItem::new(s.clone()));
    f.render_stateful_widget(
        List::new(items)
            .block(block(" Connections ", true))
            .highlight_style(
                Style::default()
                    .bg(Color::Rgb(38, 62, 75))
                    .fg(ACCENT)
                    .bold(),
            )
            .highlight_symbol(" › "),
        rows[1],
        &mut ListState::default().with_selected((!options.is_empty()).then_some(selected)),
    );
    if options.is_empty() {
        f.render_widget(
            Paragraph::new("Looking for MeshCore companions…\nPlug in a USB device or enable Bluetooth.\nDevices appear and disappear automatically.")
                .style(Style::default().fg(MUTED)).wrap(Wrap { trim: false }),
            rows[1].inner(Margin::new(2, 2)),
        );
    }
    let toggle = if show_all_ble {
        "a MeshCore only"
    } else {
        "a show all BLE"
    };
    f.render_widget(
        Paragraph::new(format!(
            "{status}\n\n↑↓ select   Enter connect   {toggle}   q quit"
        ))
        .style(Style::default().fg(MUTED))
        .wrap(Wrap { trim: false }),
        rows[2],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_details_show_radio_bytes_and_show_companion_keeps_companion_details() {
        for show_companion in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let catalogue =
                crate::catalogue::Catalogue::load(dir.path().join("catalogue.json")).unwrap();
            let mut app = App::new(
                "Test capture".into(),
                10,
                show_companion,
                "unused".into(),
                catalogue,
            );
            app.push(crate::protocol::Capture {
                at: chrono::Local::now(),
                frame: vec![0x88, 0x10, 0xa1, 0x0d, 0, 1, 2, 3, 4],
            })
            .unwrap();
            let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(160, 80)).unwrap();
            terminal.draw(|f| draw(f, &mut app)).unwrap();
            let screen: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            assert_eq!(screen.contains("Companion type"), show_companion);
            assert_eq!(
                screen.contains("WIRE BYTES / companion frame"),
                show_companion
            );
            assert_eq!(
                screen.contains("RADIO BYTES / mesh packet"),
                !show_companion
            );
            assert!(screen.contains(if show_companion {
                "0000  88 10 A1 0D 00 01 02 03 04"
            } else {
                "0000  0D 00 01 02 03 04"
            }));
            assert!(screen.contains("RSSI") && screen.contains("SNR"));
        }
    }
    #[test]
    fn catalogue_and_add_form_render_at_minimum_and_wide_sizes() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        for (w, h) in [(160, 48), (80, 30), (45, 15)] {
            let mut t = Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let mut catalogue =
                crate::catalogue::Catalogue::load(dir.path().join("catalogue.json")).unwrap();
            catalogue.add_region("test").unwrap();
            catalogue
                .add(crate::catalogue::Category::Channel, "#test", "")
                .unwrap();
            let mut frame = vec![0; 50];
            frame[0] = 0x12;
            frame[1] = 2;
            frame[2..7].copy_from_slice(b"#test");
            frame[34..].fill(1);
            catalogue.ingest(&frame).unwrap();
            let mut app = App::new(
                "Test capture".into(),
                100,
                false,
                "unused".into(),
                catalogue,
            );
            app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE))
                .unwrap();
            t.draw(|f| draw(f, &mut app)).unwrap();
            let screen: String = t
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            assert!(screen.contains("test"));
            assert!(!screen.contains("#test"));
            app.key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE))
                .unwrap();
            t.draw(|f| draw(f, &mut app)).unwrap();
            let screen: String = t
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            assert!(screen.contains("Enter save"));
            assert!(screen.contains("Esc cancel"));
            assert!(!screen.contains("Key · 32 hex"));
            app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
                .unwrap();
            app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE))
                .unwrap();
            t.draw(|f| draw(f, &mut app)).unwrap();
            let screen: String = t
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            assert!(screen.contains("read-only"));
            assert!(screen.contains('⚠'));
            app.key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE))
                .unwrap();
            t.draw(|f| draw(f, &mut app)).unwrap();
            let screen: String = t
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            assert!(screen.contains("Add manual channel"));
            assert!(screen.contains("Enter save"));
            assert!(screen.contains("Esc cancel"));
        }
    }
    #[test]
    fn renders_wide_stacked_tiny_and_help() {
        for (w, h) in [(160, 48), (80, 40), (45, 15), (30, 10)] {
            let mut t = Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let catalogue =
                crate::catalogue::Catalogue::load(dir.path().join("catalogue.json")).unwrap();
            let mut app = App::new(
                "Test capture".into(),
                100,
                false,
                "unused".into(),
                catalogue,
            );
            app.push(crate::protocol::Capture {
                at: chrono::Local::now(),
                frame: crate::protocol::sample_frame(0),
            })
            .unwrap();
            t.draw(|f| draw(f, &mut app)).unwrap();
            app.help = true;
            t.draw(|f| draw(f, &mut app)).unwrap();
            app.help_colors = true;
            t.draw(|f| draw(f, &mut app)).unwrap();
            if w >= 45 {
                let screen: String = t
                    .backend()
                    .buffer()
                    .content
                    .iter()
                    .map(|c| c.symbol())
                    .collect();
                assert!(screen.contains("Selected row"));
                assert!(screen.contains("Direct text"));
            }
            app.help = false;
            app.page = Page::Channels;
            app.channels_table.select(Some(0));
            t.draw(|f| draw(f, &mut app)).unwrap();
            if w >= 80 && h >= 40 {
                let screen: String = t
                    .backend()
                    .buffer()
                    .content
                    .iter()
                    .map(|c| c.symbol())
                    .collect();
                assert!(screen.contains("Public"));
                assert!(screen.contains("Built-in channel"));
                assert!(screen.contains("cannot be deleted"));
            }
            t.draw(|f| picker(f, &["USB / Test companion".into()], 0, "Ready", false))
                .unwrap();
            t.draw(|f| picker(f, &[], 0, "No devices found", false))
                .unwrap();
        }
    }
    #[test]
    fn radio_rows_ignore_payload_previews_and_catalogue_summary_suffixes() {
        for n in 0..6 {
            let frame = crate::protocol::sample_frame(n);
            let mut decoded = crate::protocol::decode(&frame);
            let size = frame.len() - 3;
            decoded.summary = "TYPE-SPECIFIC PREVIEW / REGION / CHANNEL".into();
            let entry = crate::app::Entry {
                id: 7,
                capture: crate::protocol::Capture {
                    at: chrono::Local::now(),
                    frame,
                },
                decoded,
            };
            let mut t = Terminal::new(ratatui::backend::TestBackend::new(80, 2)).unwrap();
            t.draw(|f| {
                f.render_widget(
                    Table::new(
                        [packet_row(&entry)],
                        [
                            Constraint::Length(8),
                            Constraint::Min(12),
                            Constraint::Length(5),
                            Constraint::Length(4),
                        ],
                    ),
                    f.area(),
                )
            })
            .unwrap();
            let screen: String = t
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            assert!(screen.contains(&format!("Flood · {size} B")));
            assert!(screen.contains("1 B"));
            assert!(!screen.contains("TYPE-SPECIFIC"));
        }
    }
}
