# AGENTS.md — AI Context for Offline Secure Messenger

This file provides context for AI coding assistants working on this repository.

## Repository Overview

Two-component secure messaging system:
- **OSM** — C firmware (LVGL 9.4 + SDL2 desktop simulator, target: ESP32-S3)
- **Companion App (CA)** — Kotlin Multiplatform (desktop JVM + Android)

Plaintext never leaves the OSM. The CA only handles ciphertext.

## BLE Transport Architecture

The OSM acts as a **BLE GATT server** (peripheral). The CA acts as a **GATT
client** (central). This mirrors the hardware target (LILYGO T-Deck with
BLE 5.0) where the phone initiates connections to the OSM device.

```mermaid
sequenceDiagram
    participant CA as Companion App (Central)
    participant OSM as OSM Device (Peripheral)
    CA->>OSM: BLE scan → find service 0xFE00
    CA->>OSM: Connect
    CA->>OSM: Discover services
    CA->>OSM: Read INFO (0xFE05) → device name
    CA->>OSM: Subscribe to TX notifications (0xFE02)
    CA->>OSM: Write ciphertext to RX (0xFE03)
    OSM-->>CA: ACK via TX notification
    OSM-->>CA: Outbound ciphertext via TX notification
    CA->>OSM: ACK via RX write
```

### GATT Service Definition

| UUID | Name | Properties | Direction | Description |
|------|------|------------|-----------|-------------|
| `0000fe00-…` | Service | — | — | Custom OSM service |
| `0000fe02-…` | TX | Notify | OSM → CA | Outbound ciphertext + ACKs |
| `0000fe03-…` | RX | Write Without Response | CA → OSM | Inbound ciphertext + ACKs |
| `0000fe04-…` | STATUS | Read | OSM → CA | Connection status (reserved) |
| `0000fe05-…` | INFO | Read | OSM → CA | Device name string |

Full 128-bit UUIDs use the Bluetooth SIG base: `0000XXXX-0000-1000-8000-00805f9b34fb`

### Fragmentation Protocol

Messages are fragmented to fit BLE MTU (200 bytes). Wire format per fragment
(little-endian):

```
[flags:1][seq:2][total_len:2 (START only)][payload:N]
```

Flags: `START=0x01`, `END=0x02`, `ACK=0x04`. ACK msg_id = first 8 bytes of
SHA-512 of the reassembled payload (TweetNaCl's `crypto_hash`).

## Transport Source Structure

```
osm/src/transport/
├── transport.h          # Public API + constants (MTU, UUIDs, flags)
├── transport_common.c   # Shared logic: fragmentation, reassembly, ACK, broadcast
├── transport_tcp.c      # TCP backend (desktop simulator, OSM listens on port)
└── transport_ble.c      # BLE backend (BlueZ GATT server via D-Bus/libdbus-1)
```

Only one backend is compiled at a time — controlled by `TRANSPORT_BLE` CMake
option. `transport_common.c` is always included.

## Building

### OSM — TCP (desktop simulator, default)

```bash
cd osm && mkdir -p build && cd build
cmake .. && make -j$(nproc)
./secure_communicator                 # interactive (port 19200)
./secure_communicator --test          # run 69 built-in tests
./secure_communicator --port 19201 --name Bob
```

### OSM — BLE (BlueZ GATT server)

Requires `libdbus-1-dev` and a BlueZ-managed BLE adapter.

```bash
cd osm && mkdir -p build_ble && cd build_ble
cmake .. -DTRANSPORT_BLE=ON && make -j$(nproc)
sudo ./secure_communicator            # needs root for BlueZ D-Bus
```

### Desktop Companion App

```bash
cd companion-app
./gradlew :desktopApp:run
```

### Android Companion App

Requires Android SDK (API 34+), JDK 17+.

```bash
cd companion-app
./gradlew :androidApp:assembleDebug
# Install via adb install androidApp/build/outputs/apk/debug/*.apk
```

## Running Tests

### OSM built-in tests

```bash
cd osm/build && ./secure_communicator --test
```

69 automated tests: screens, navigation, input, CRUD, crypto, transport.

### E2E integration tests (TCP transport)

```bash
cd osm/build && cmake .. && make -j$(nproc)
cd ../..
SDL_VIDEODRIVER=dummy python3 -m pytest tests/e2e_test.py -v
```

43 tests: full KEX flows, encrypted messaging, outbox persistence, reconnection,
adversarial scenarios (disconnect, restart, overflow, corrupt fragments).

Requires: `pytest`, `pynacl` (`pip install pytest pynacl`).

### Clearing persistent data

```bash
rm osm_data.img          # from repo root (or wherever OSM runs)
rm /tmp/osm_*/osm_data.img  # test temp dirs (auto-cleaned)
```

### BLE integration tests

Requires a BLE adapter and an OSM running with BLE transport.

```bash
# Terminal 1: start OSM with BLE
cd osm/build_ble && sudo ./secure_communicator

# Terminal 2: run BLE tests
uv run pytest tests/ble_integration_test.py -v -s
```

Tests skip gracefully if no BLE adapter is available.

## Key Conventions

- C11, LVGL 9.4 API, TweetNaCl for crypto
- PEP 723 inline metadata for Python test scripts (`uv run` compatible)
- **Persistent storage**: All data lives inside a LittleFS filesystem image
  (`osm_data.img`). Delete the file to reset all state.
- Files stored in LittleFS: `contacts.json`, `identity.json`, `messages.json`,
  `pending_keys.json`, `outbox.json`
- Desktop-only code guarded by `#ifndef OSM_MCU_BUILD`
- OSM default TCP port: 19200 (scan range 19200–19209)

## HAL (Platform Abstraction Layer)

The OSM firmware is portable between desktop (SDL2) and MCU (ESP32-S3) via HAL
modules in `osm/src/hal/`:

| Module | Header | Desktop Impl | Purpose |
|--------|--------|-------------|---------|
| Storage | `hal_storage.h` | `hal_storage_filebd.c` | LittleFS init/mount/get (file-backed block device) |
| RNG | `hal_rng.h` | `hal_rng_posix.c` | Random bytes (`/dev/urandom`) |
| Log | `hal_log.h` | `hal_log_posix.c` | `fprintf(stderr, ...)` |

Helper: `hal_storage_util.h` — inline `hal_storage_read_file()` / `hal_storage_write_file()`
wrapping LittleFS open/read/write/close into single calls.

### LittleFS Configuration (Desktop)

- Block size: 4096, Block count: 256 (1 MB virtual flash)
- Backing file: `osm_data.img` in working directory
- Auto-formats on first use (mount fails → format → mount)
