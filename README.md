# ◈ meshages

A Rust TUI for inspecting raw radio packets received by a MeshCore companion.
The connection picker automatically watches USB and BLE devices while it is open.
Choose a companion and watch received packets alongside their decoded fields.

```sh
cargo run                         # live USB + BLE connection picker
cargo run -- --serial /dev/cu.usbmodem123 --baud 115200
cargo run -- --ble MeshCore       # select a discovered name/address/identifier
cargo run -- --scan-ble           # bounded BLE discovery diagnostics
cargo run -- --tcp 192.168.1.50:5000
cargo run -- --record capture.jsonl
cargo run -- --replay capture.jsonl
```

Devices are added and removed automatically. The selected device stays selected
when other devices arrive, disappear, or update their signal strength. Use ↑/↓
and Enter to connect, **a** to toggle all BLE devices for troubleshooting, and
**q** or Esc to quit. Returning from the inspector starts discovery again.

USB ports are enumerated about twice a second. New ports appear only after a
valid MeshCore `DEVICE_QUERY` response. Verification runs in the background and
can take up to three seconds per port; ports that are booting or busy are retried
after ten seconds. Confirmed ports are left alone until unplugged. Probing sends
only a device-info query at `--baud` (115200 by default). `--serial PATH` bypasses
automatic identification when necessary.

BLE uses the same `btleplug` APIs on macOS, Linux, and Windows: scan for nearby
advertisements and periodically retrieve system-connected UART devices. Already
connected companions stay discoverable even when they stop advertising. Nearby
entries disappear after 15 seconds without fresh discovery events; system
entries are refreshed about every two seconds and removed when the system no
longer reports them. Radio-off and adapter failures are retried automatically.
The list shows MeshCore names and UART service matches by default; unrelated
devices stay hidden unless **a** is enabled.

Discovery does not maintain a saved-device cache or use OS-specific pairing
states. Entries are labeled **nearby** or **system**; they are candidates until
connection validates the companion characteristics. Device identifiers remain
opaque; `--ble` matches the names or identifiers returned by discovery. A paired,
disconnected device must advertise or be reported by the system to appear.
`--scan-ble` runs the same discovery for roughly 12 seconds and prints all results.

Command-line sources skip the picker. Pair through the operating system if the
companion requires a PIN. On macOS, allow Bluetooth access for your terminal in
System Settings → Privacy & Security → Bluetooth. Linux builds need BlueZ,
D-Bus development headers (`libdbus-1-dev`, `pkg-config` on Debian/Ubuntu), and
serial-port permissions.
Discovery itself does not pair, connect, or disconnect companions.

## Interface

On wide terminals, packets are on the left and details on the right. Below 110
columns the panels stack. The details pane gets the larger share of the width.
Packet types have consistent colors; the selected row and focused pane have
distinct highlights.

The detail pane keeps packet type, reception time, size, and warning/encryption
status at the top while the rest scrolls. Teal **GENERAL PACKET** and violet
**PAYLOAD** bars separate radio measurements and routing from the payload's
contents. The parsing tree follows packet byte order rather than grouping fields
by purpose. Each field shows its hexadecimal offset, byte length in decimal,
literal bytes, and interpretation where known (`bytes → value`). Nested rows
decompose packed header/path bits, transport codes, path entries, and advert
application data. Multi-byte integers show their little-endian interpretation;
advert timestamps also show UTC time. Adverts therefore show the key, timestamp,
signature, then application flags/location/features/name in their encoded order.
Paths use compact rows: the encoded length byte followed by count × entry width,
then fixed-width hashes such as `A217 → B903`, wrapping as needed. Trace paths pair
each raw sample with its SNR, such as `04 (+1.00 dB) → F8 (-2.00 dB)`.

Catalogue matches are marked as annotations beside the corresponding scope code
or channel hash. Encrypted data remains ciphertext; reserved, unknown, and
truncated fields retain their bytes without invented interpretations. Advert
fields and signatures remain explicitly unverified. The default view keeps RX
signal metadata separate from the radio-byte offsets; `--show-companion` instead
includes the companion type, SNR, and RSSI bytes in wire order, with offsets that
match the complete companion-frame dump.

The complete offset/hex/ASCII dump follows the decoded fields. Bytes are colored
by structure, with a legend: teal header, periwinkle scope codes, blue path,
violet payload, and muted companion metadata when shown. Its column count adapts
to the pane width. **Enter** expands the selected packet to the full body area and
pauses follow so new arrivals do not replace it. **Enter** or **Esc** restores the
two panels. Capture continues throughout.

The default view focuses on radio packets: it hides the companion type field and
the **RADIO BYTES** dump starts at the MeshCore header, with offset zero. The
three RX-log metadata bytes (companion type, SNR, RSSI) are excluded from that
dump; RSSI and SNR remain visible as measurements. Search uses the same fields
and bytes shown in the current view.

`--show-companion` includes companion responses/pushes, shows the companion type
field, and uses the complete companion frame in **WIRE BYTES**. Serial/TCP length
framing has already been stripped by the transport layer and is not part of
either dump. Recordings and JSONL exports retain complete companion frames for
replay, regardless of the display mode.

Every raw RX entry uses the same two-line format, including unknown or malformed
packets (unavailable fields show `—`):

| Column | First line | Second line |
| --- | --- | --- |
| TIME | Reception time | Capture ID |
| TYPE / ROUTE · B | Packet type, plus `⚠` if needed | Route mode and mesh packet size in bytes |
| RX¹ | RSSI in dBm | SNR in dB |
| PATH | Encoded entry count | Bytes per encoded entry |

Mesh size excludes the three companion RX-log metadata bytes. Trace path entries
contain signal samples; other paths contain routing hashes. Advert names, channel
hashes, and catalogue candidates remain in the details and are searchable.
Companion responses shown with `--show-companion` keep their own summaries and show
`—` for radio fields that are not present.

Type colors describe the packet category, not signal strength, validity, or
authentication. They use the terminal's standard color palette:

| Color | Meaning |
| --- | --- |
| Cyan | Advert |
| Green | ACK |
| Magenta | Channel text or data |
| Yellow | Direct text |
| Red | `Malformed RX` label |
| Blue | Other radio packet types |
| Muted slate gray (`#747c8d`) | Non-radio companion frames shown with `--show-companion`, including discovery pushes and errors |

Recognizable packet types keep their type color even if decoding produces a
warning; `⚠` marks that warning, and the detail warning text is yellow. UI accents
use fixed RGB colors: teal (`#59dcc4`) for focused borders/headings/follow, gray
(`#8797ad`) for secondary information, and a muted blue-green (`#263e4b`) background
plus bold text for the selected row. The background is `#0f141e`, with panels in
`#161d29`. Press **?**, then **Tab**, for a live color legend.

| Key | Action |
| --- | --- |
| ↑ / ↓ or j / k | Select a packet; scroll when details are focused |
| Tab | Switch panel focus |
| Enter | Expand / restore packet details (outside search) |
| PageUp / PageDown | Move or scroll ten rows |
| Home / g | Oldest visible packet |
| End / G / f | Latest packet and follow new arrivals |
| Space | Toggle follow; capture continues while inspecting |
| / | Live search over types, summaries, decoded fields, and hex |
| Enter / Esc in search | Apply / clear search |
| e | Append visible packets to `meshages-export.jsonl` |
| r / 2 | Open local regions |
| c / 3 | Open imported channels |
| 1 | Return to packets |
| ? / F1 | Open keyboard and protocol help |
| Tab / ← / → in help | Switch between key help and the color legend |
| Esc | Restore panels, clear search, or return to connections after dismissing help |
| q / Ctrl+C | Quit |

Use `--export PATH` to choose the snapshot destination, `--capacity N` to change
the default 10,000-packet memory limit, and `--show-companion` for companion traffic
and protocol details. The footer reports eviction and connection errors.
Following and filtering affect display only. There is no automatic reconnection;
Esc returns to the picker. Recordings span connections chosen during a session.

`--record PATH` appends every received companion frame, including frames hidden
by the RX-only view, before memory eviction. Files are JSON Lines, with an ISO
reception timestamp (`at`) and companion bytes (`frame`, an array of integers).
Snapshots append the currently visible retained packets. Repeated exports can
therefore include duplicate records. These files may contain sensitive traffic.
Replay reads this same format and obeys the retention limit.

## Local catalogue

Manually added regions and channels are stored in the per-user configuration
directory, resolved by [`dirs::config_dir`](https://docs.rs/dirs/latest/dirs/fn.config_dir.html):

| Platform | Default catalogue path |
| --- | --- |
| macOS | `~/Library/Application Support/meshages/catalogue.json` |
| Linux | `~/.config/meshages/catalogue.json`, or `$XDG_CONFIG_HOME/meshages/catalogue.json` when configured |
| Windows | `%APPDATA%\meshages\catalogue.json` (Roaming AppData) |

Use `--catalogue PATH` to choose a different file; relative paths are relative to
the current directory. The default is independent of the working directory. If
the user configuration directory cannot be determined, supply `--catalogue PATH`.
Existing project-local catalogues are not migrated automatically; they can be
opened explicitly with `--catalogue .meshages/catalogue.json`.

The catalogue is loaded before opening the TUI. The directory and file are
created on the first manual save, and later changes are saved automatically.
Invalid files are reported without being overwritten. Saves replace a complete
file, preserving the old contents if writing fails.

At every connection, the tool reads the companion's default flood scope and all
configured channel slots into memory. Device entries are read-only and are never
written to the catalogue file. Switching companions clears the previous device
layer and loads the new one; manual entries remain. There is no network discovery
or deletion history. Adding or removing a manual entry affects only this file.

Both pages merge the manual and device layers with these rules:

| Entries | Display and behavior |
| --- | --- |
| Same name and full key | One row; source is `manual`, `device (read-only)`, or `manual + device` |
| Same name, different keys | Separate rows marked **⚠**; neither key overwrites the other |
| Different names, same key | Separate aliases marked **↔** |
| Same device channel in several slots | One row, with all slot numbers in its details |

Channels also include the standard **Public** channel as a read-only built-in.
It is available without a connected device, including during replay, and is never
written to the manual catalogue. A matching name and full key from the companion
merge into this row, labeled `built-in + device`, with its device slots shown.
Other channels named Public with different keys remain separate conflicts. Slot
numbers alone never identify the built-in channel. Public cannot be deleted or
added again as a redundant manual entry.

Identity comparisons use full keys, not short fingerprints or packet hashes.
Region names are displayed and stored without a leading `#`; one is stripped
from input if supplied. Case is preserved. Exact manual duplicates are ignored.
**d** or Delete removes
only a manual copy. Built-in and device-only entries cannot be deleted. On a `manual + device`
row, removing the manual copy leaves the device entry visible and read-only.

Press **r** for Regions. The current companion's default is marked **★ device
default**. Press **a** to enter a region name, Enter to save, and Esc to cancel.
Names are case-sensitive. The 128-bit key is always derived automatically;
there is no manual key field or private-region option. Manual regions are stored
as a list of plain names in JSON. The legacy `#` prefix is added internally only
when deriving the key, so `city` uses the first 16 bytes of `SHA256("#city")`.
The device's default remains read-only, and its key is used exactly as reported
by the companion. Older firmware that cannot return a default still supports
manual catalogue entries.

The catalogue is flat. Repeater region hierarchies organize each repeater's
configuration; parent relationships are not present in raw packets and do not
participate in region key derivation or transport-code matching. A child's key
comes from its own name, without its parent's name. See the upstream
[hierarchy commands](https://github.com/meshcore-dev/MeshCore/blob/main/docs/cli_commands.md#region-management-v110)
and [region matching](https://github.com/meshcore-dev/MeshCore/blob/main/src/helpers/RegionMap.cpp#L158-L189).

Press **c** for Channels. Use **a**, Tab, Enter, Esc, and **d**/Delete
controls to add or remove manual channels. Leaving the key blank for `#name`
derives a hashtag channel's 128-bit key from its exact name. Public is already
available as a built-in. Other channel names require a 32-digit hexadecimal
key. An explicit key overrides name-based derivation. Device slot numbers appear
in the entry details. Channel decryption remains a future extension.

Both pages show key fingerprints. Manual channel keys are stored as hexadecimal
strings in the plain-text JSON file, including private-channel secrets. Device
metadata in `--record` captures includes keys too. Replay can load that metadata
into the in-memory device layer without changing the catalogue file.

Tab switches between Regions and Channels; **1** or Esc returns to packets.
Capture continues on these pages and while the add form is open.

Catalogue entries annotate both new and retained packets, and their names are
searchable. Region candidates match the first transport code using HMAC-SHA256
over payload type and payload; the second transport code remains displayed as
raw data. Channel candidates match the visible channel hash. These codes/hashes
are only 16/8 bits, so candidates are marked with `?`; a match is not proof of
identity or successful decryption. Multiple matches are displayed together.

## Protocol and scope

Live capture consumes `PUSH_CODE_LOG_RX_DATA` (`0x88`): signed quarter-dB SNR,
signed RSSI, then the raw mesh packet. USB/TCP frames use `>` plus a little-endian
16-bit length; app commands use `<`. BLE notifications carry companion frames
directly. Connecting subscribes to notifications and sends `APP_START`, then
queries device info, the default flood scope, and configured channels. These
queries share one startup sequence across USB, TCP, and BLE. This tool does not
configure regions/channels, transmit mesh messages, or drain the message queue.
Firmware must expose raw RX logs over the selected interface.

Decoding follows the upstream firmware's
[companion implementation](https://github.com/meshcore-dev/MeshCore/blob/main/examples/companion_radio/MyMesh.cpp),
[packet encoding](https://github.com/meshcore-dev/MeshCore/blob/main/src/Packet.cpp),
[packet definitions](https://github.com/meshcore-dev/MeshCore/blob/main/src/Packet.h),
[advert data](https://github.com/meshcore-dev/MeshCore/blob/main/src/helpers/AdvertDataHelpers.h),
[serial framing](https://github.com/meshcore-dev/MeshCore/blob/main/src/helpers/ArduinoSerialInterface.cpp),
[region keys and transport codes](https://github.com/meshcore-dev/MeshCore/blob/main/src/helpers/TransportKeyStore.cpp),
and [channel hashes](https://github.com/meshcore-dev/MeshCore/blob/main/src/helpers/BaseChatMesh.cpp).

Encrypted messages remain encrypted: the tool decodes their visible envelope,
not plaintext. Advert signatures are displayed but not verified. Unknown payloads
and unsupported versions retain their bytes. Path hashes do not uniquely identify
nodes; direct paths contain remaining routing entries, and trace paths contain
signal samples. Malformed packets stay inspectable with a warning.

The input channel is bounded to 2,048 events. If rendering or recording cannot
keep up, dropped frames are reported in the footer. Disk errors stop recording
with an error instead of silently losing data. Contact-based identity resolution,
key-based decryption, and active tools are future work.

Modules separate transport (`source`, `ble`, `usb`), live device presence
(`discovery`), connection selection (`connections`), wire decoding (`protocol`),
local metadata (`catalogue`), companion startup queries (`companion`), application
state (`app`), rendering (`ui`), and startup (`main`). BLE uses
btleplug; rendering uses Ratatui and Crossterm.

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Automated checks exercise malformed packets, incremental framing, path encoding,
USB firmware identification and hotplug, BLE expiry and system-device removal,
stable connection selection, packet retention, filtering, manual catalogue
persistence, read-only device metadata, duplicates/conflicts/aliases, startup
queries, region matching, and terminal rendering.
Actual USB/BLE behavior requires a companion for hardware verification.
