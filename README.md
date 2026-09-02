# ESP32-S3 AdBlocker

A fork of `esp32-c3-adblock` for the **ESP32-S3 SuperMini (ESP32-S3FH4R2)**: a
Pi-hole-style DNS ad-blocker with 4 MB flash and 2 MB QSPI PSRAM.

> 📰 Featured on [Tom's Hardware](https://www.tomshardware.com/networking/clever-hacker-fits-537-000-domains-in-a-tiny-usd5-esp32-ad-blocking-dongle-firmware-uses-only-around-50kb-of-ram-and-can-answer-blocked-lookups-in-10-milliseconds), [XDA Developers](https://www.xda-developers.com/this-tiny-esp32-powered-gadget-blocks-537000-domains-only-uses-50kb-of-ram/), and [Korben](https://korben.info/en/half-million-ad-blocking-domains-50kb-ram-esp32.html).

The trick everyone misses: you don't need to keep the blocklist in RAM. Store the
domains as **sorted 40-bit hashes in flash** and binary-search them. 140,000+ domains
fit in ~0.7 MB of flash and are matched in ~10 ms, using **~50 KB of RAM**.

```
query in ──▶ extract domain ──▶ FNV-1a hash (+ parent suffixes)
         ──▶ binary-search the flash hash table
              ├─ hit  ──▶ answer 0.0.0.0   (sinkholed)
              └─ miss ──▶ forward to upstream resolver, relay the reply
```

## Why this is interesting

Most ESP32 DNS sinkholes load the blocklist (domain *strings*) into RAM, so they
demand PSRAM. This project stores fixed **5-byte (40-bit) hashes in flash** instead:

| | string-in-RAM approach | this (hash-in-flash) |
|---|---|---|
| Hardware | ESP32 + PSRAM (~$8) | ESP32-S3 SuperMini, 2 MB PSRAM |
| 141k domains | ~2.5 MB of RAM | **0.67 MB of flash** |
| RAM used | most of it | **~50 KB** |
| Lookup | string compare | ~18 flash reads (~10 ms incl. WiFi RTT) |
| Collisions | n/a | 0 at 141k (1 at 537k) |

**Why 40 bits?** It's the sweet spot for this flash budget. Collisions follow the
birthday bound — at 141k domains you get ~0, at 537k about 1 (i.e. one unlucky
domain gets over-blocked). Dropping to 32 bits would save 20% of the flash but
cost ~7 collisions at 250k; going to 64 bits wastes 3 bytes per domain to solve
a problem you don't have.

The hash-in-flash approach works on bigger chips too. This fork keeps the same
4 MB dual-OTA partition layout as the original project; the S3's PSRAM is
available for future enhancements but is not required for the blocklist.

## Hardware

- An **ESP32-S3 SuperMini / ESP32-S3FH4R2**, with 4 MB flash and 2 MB QSPI PSRAM
- Power it from a **stable USB source** (a phone charger or your router's USB port).
  Cheap/loose USB-C→A adapters can brown out the radio during WiFi transmit.
- A **USB-A → USB-C dongle** lets it plug straight into the spare USB port on the
  back of most routers — no power supply, no extra box.

### Enclosure

A printable C3 SuperMini enclosure remains available at
[`hardware/esp32-c3-supermini-enclosure.stl`](hardware/esp32-c3-supermini-enclosure.stl),
but it is not designed for the S3 SuperMini.

Printing notes:
- No supports needed; 0.2 mm layers, ~15% infill is plenty.
- Keep the antenna area clear; do not bury the board in solid plastic or place metal
  near it, or WiFi RSSI will suffer.
- Leave the vents open: the board idles around 45–55 °C.

## Build & flash (PlatformIO)

One USB flash to get going — after that, **firmware and blocklist both update over WiFi** (see below).

> ⚠️ Use a **current PlatformIO** — the VSCode PlatformIO extension's bundled core, or
> `pip install -U platformio` in a venv. The distro/apt `platformio` package (e.g. 4.3.4) is
> too old and fails with `AttributeError: ... 'resultcallback'` (issue #4). A browser
> installer is available in the [`docs`](docs) directory when its release artifacts are hosted.

```bash
# 1. (optional) set WiFi creds at compile time — or skip this and use the
#    on-device setup portal (below). secrets.h is gitignored, stays local.
cp src/secrets.example.h src/secrets.h
#    then edit src/secrets.h -> WIFI_SSID / WIFI_PASS

# 2. build the blocklist hash table (default = StevenBlack base + Hagezi Light,
#    ~140k domains, WhatsApp/social safe)
python3 tools/build_blocklist.py data/blocklist.bin

# 3. flash firmware + the blocklist filesystem (the one and only USB flash)
pio run -e s3 -t upload
pio run -e s3 -t uploadfs

# 4. watch it boot, note the IP / open the dashboard
pio device monitor          # -> http://c3adblock.local
```

### WiFi setup (no re-flash needed)

If it can't connect (or you never set `secrets.h`), it starts an open access point
**`C3-AdBlock-XXXX`** with a captive portal — join it from a phone, pick your network,
type the password, done. To move it to a new network later, open
`http://c3adblock.local/forgetwifi`. The C3-only GPIO9 BOOT-button reset behavior is
intentionally not used on the S3 SuperMini.

## Over-the-air updates (no more USB)

The dashboard at **http://c3adblock.local** does it all:

- **Blocklist** — drop a freshly built `blocklist.bin` into *Blocklist → Upload*, or set a
  URL under *Remote auto-update* and the device pulls a prebuilt `blocklist.bin`
  on a schedule (e.g. a GitHub release asset — update it once, every device fetches it).
- **Firmware** — upload `.pio/build/s3/firmware.bin` under *Firmware → OTA update*; the
  device verifies it and reboots into the new image. Or push over WiFi from the CLI:
  ```bash
  pio run -t upload --upload-port c3adblock.local --upload-protocol espota
  ```

**4 MB flash tradeoff:** firmware OTA needs *two* app slots, which leaves ~1.3 MB for the
blocklist (**~250k domains max**). The aggressive 537k "ultimate" list only fits the
single-app partition table (no firmware OTA). Pick your tradeoff in `partitions.csv`.

## Use it

Point a device's DNS at the C3's IP, or add it as a **secondary resolver** behind
your main DNS. Test:

```bash
dig @<c3-ip> doubleclick.net   # -> 0.0.0.0  (blocked)
dig @<c3-ip> github.com        # -> real IP  (forwarded)
```

## Reliability and diagnostics

This fork adds recovery mechanisms intended for unattended network use:

- Upstream DNS replies are matched to their request by source, transaction ID, and
  question before they are relayed. Stale UDP replies are drained, preventing a timeout
  from shifting later DNS responses onto the wrong client query.
- A 5-second ESP task watchdog detects a genuinely stalled firmware task. Long-running
  DNS, download, WiFi connection, and provisioning loops feed it deliberately.
- A warning is recorded after 10 consecutive upstream DNS failures. The device restarts
  after 30 consecutive failures, after 60 seconds without a successful response following
  prior success, or after 30 seconds continuously disconnected from WiFi.
- Important events are retained in LittleFS at `/diagnostics.log`, capped at about 24 KB
  to limit flash wear. Entries use UTC timestamps after NTP synchronization, with uptime
  as a fallback during early boot. DNS queries are not logged individually.
- Open `http://c3adblock.local/logs` for the reset reason, previous automatic restart
  reason, and persistent log. `GET /logs.json` returns the raw log; `POST /logs/clear`
  clears it. The dashboard's **Diagnostics** link opens the same page.
- `/stats.json` also reports DNS successes/failures, reset and restart reasons, uptime,
  free heap, WiFi RSSI, and available PSRAM.

## Gotchas (learned the hard way)

- **ModemManager** (default on Fedora/Ubuntu) grabs `/dev/ttyACM0` and toggles
  DTR/RTS, which **resets the C3** and blocks serial. Fix:
  ```bash
  sudo systemctl stop ModemManager
  echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```
- The S3's USB-Serial-JTAG console can swallow early boot output until the host
  connects (`while(!Serial)` helps).
- DNS clients add an **EDNS OPT** record; a blocked reply must contain only the
  question + answer (ANCOUNT=1, NSCOUNT=ARCOUNT=0) or it's malformed.

## Done / how it could grow

- ✅ Web dashboard — per-client block/allow counts, ban a client, add custom domains
- ✅ mDNS (`c3adblock.local`) for discovery
- ✅ OTA — firmware + blocklist update over WiFi, plus scheduled remote blocklist pulls
- ✅ Captive-portal WiFi setup (no hardcoded creds)
- ✅ S3 reliability recovery: upstream-response validation, task watchdog, WiFi/DNS
  health monitoring, persistent diagnostics, and restart-reason reporting
- ⬜ Bucketed prefix index — ~18 flash reads/lookup → ~1–2 (issue #3), the throughput win
- ⬜ Act as the DHCP server (hand itself out as DNS) for true plug-and-play

## Credits

Inspired by [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) — the
"answer 0.0.0.0 for blocklisted domains" idea. This is an independent from-scratch
implementation focused on the hash-in-flash optimization for PSRAM-less chips.

## License

MIT — see [LICENSE](LICENSE).
