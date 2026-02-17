# Offline Secure Messenger

A secure offline messaging system with two components:

1. **OSM** (Offline Secure Messenger) — a microcontroller-based device with a
   320×240 display and BlackBerry-style keyboard. Handles all encryption,
   decryption, and key management. Plaintext never leaves this device.
2. **Companion App** (CA) — an Android/desktop app that bridges encrypted
   ciphertext between the OSM and the user's regular messaging apps via BLE.

The host device (phone/PC) is treated as a compromised communications pipe —
it only ever sees ciphertext.

## Architecture

```mermaid
graph LR
    subgraph "Person A"
        OSM_A[OSM-A Device]
        CA_A[CA-A Phone]
        APP_A[Signal / etc.]
    end
    subgraph "Person B"
        OSM_B[OSM-B Device]
        CA_B[CA-B Phone]
        APP_B[Signal / etc.]
    end

    OSM_A -->|ciphertext via BLE| CA_A
    CA_A -->|user copies| APP_A
    APP_A -.->|internet| APP_B
    APP_B -->|user pastes| CA_B
    CA_B -->|ciphertext via BLE| OSM_B
    OSM_B -->|decrypted plaintext| OSM_B
```

## Repository Structure

```
offline-secure-messenger/
├── osm/                    # OSM device firmware + desktop simulator
│   ├── CMakeLists.txt
│   ├── lv_conf.h
│   ├── lvgl/               # LVGL 9.4 (git submodule)
│   ├── littlefs/           # LittleFS library (vendored)
│   │   └── bd/             # Block device backends (filebd, rambd)
│   ├── src/                # C source — LVGL UI, data, crypto, transport
│   │   ├── hal/            # Platform Abstraction Layer (storage, rng, log)
│   │   ├── data/           # Persistence (contacts, messages, identity)
│   │   ├── transport/      # TCP / BLE transport backends
│   │   └── screens/        # LVGL screen implementations
│   └── tests/
├── companion-app/          # Companion App (Kotlin Multiplatform + Compose)
│   ├── shared/             # Common code (model, transport, UI)
│   └── desktopApp/         # Desktop entry point
├── tests/                  # Integration tests (51 E2E tests)
├── AGENTS.md               # AI assistant context (architecture, build, test)
├── LICENSE
└── README.md               # This file
```

## Components

### OSM (Offline Secure Messenger)

Desktop simulator built with C + LVGL 9.4 + SDL2. See [`osm/README.md`](osm/README.md)
for build instructions, screen descriptions, and technical details.

**Target hardware**: LILYGO T-Deck (ESP32-S3, 320×240, BLE 5.0, QWERTY keyboard)

### Companion App

Kotlin Multiplatform + Compose Multiplatform targeting Android and desktop.
Communicates with the OSM over TCP (desktop simulation) or BLE (Android).
See [`companion-app/README.md`](companion-app/README.md) for details.

## Build Targets

| Target | Transport | Build Command | Notes |
|--------|-----------|---------------|-------|
| **OSM (TCP)** | TCP socket | `cmake .. && make` | Desktop simulator (default) |
| **OSM (BLE)** | BlueZ GATT | `cmake .. -DTRANSPORT_BLE=ON && make` | Requires `libdbus-1-dev`, root for BlueZ |
| **Desktop CA** | TCP | `./gradlew :desktopApp:run` | JDK 11+, auto-discovers OSMs |
| **Android CA** | BLE | `./gradlew :androidApp:assembleDebug` | Android SDK API 34+, JDK 17+ |

### BLE Transport

In BLE mode the OSM runs as a GATT server (peripheral) advertising service
UUID `0000fe00-0000-1000-8000-00805f9b34fb`. The CA connects as a GATT client
and exchanges ciphertext fragments via the TX (notify, `0xFE02`) and RX
(write, `0xFE03`) characteristics. An INFO characteristic (`0xFE05`) provides
the device name. Messages are fragmented to fit the BLE MTU (200 bytes).

## Quick Start

```bash
# Clone with submodules
git clone --recurse-submodules <repo-url>
cd offline-secure-messenger

# Build and run OSM simulator (TCP, default)
cd osm
mkdir -p build && cd build
cmake .. && make -j$(nproc)
./secure_communicator              # Interactive mode (port 19200)
./secure_communicator --test       # Automated tests (69 built-in + 51 E2E)

# Build OSM with BLE transport (optional)
mkdir -p ../build_ble && cd ../build_ble
cmake .. -DTRANSPORT_BLE=ON && make -j$(nproc)
sudo ./secure_communicator         # Needs root for BlueZ D-Bus

# In another terminal — build and run Companion App
cd companion-app
./gradlew :desktopApp:run
```

### Launch a Full Test Session (Alice + Bob)

A convenience script launches two OSM instances and two Companion Apps for
manual end-to-end testing:

```bash
# Launch (2 OSM windows + 2 CA windows)
./tests/launch_test_session.sh

# Stop all
./tests/launch_test_session.sh stop
```

This creates OSM-Alice (port 19200) and OSM-Bob (port 19201) in separate
working directories, then builds and launches matching Companion Apps.

## E2E Integration Tests

The 51 end-to-end tests exercise the full OSM↔CA protocol over TCP: key
exchange, encrypted messaging, outbox persistence, reconnection, adversarial
scenarios, contact rename, screen navigation, and more.

```bash
# Build OSM first
cd osm/build && cmake .. && make -j$(nproc) && cd ../..

# Run all tests (headless)
SDL_VIDEODRIVER=dummy python3 -m pytest tests/e2e_test.py -v

# Run a single test
SDL_VIDEODRIVER=dummy python3 -m pytest tests/e2e_test.py::test_full_kex_and_multi_message -v
```

**Requirements**: Python 3.10+, `pytest`, `pynacl` (for crypto tests).

```bash
pip install pytest pynacl
```

## Persistent Storage

All OSM data (identity, contacts, messages, outbox, pending keys) is stored
inside a **LittleFS** filesystem image (`osm_data.img`). On the desktop
simulator this is backed by a regular file; on the MCU target it maps to SPI
flash.

```bash
# Clear all persistent data and start fresh
rm osm_data.img

# The file is auto-created on first run (1 MB, formatted automatically)
```

The storage layer is abstracted behind a **Platform Abstraction Layer (HAL)**
so the same application code runs on both desktop and MCU:

| HAL Module | Desktop Implementation | MCU Implementation |
|---|---|---|
| `hal_storage` | `lfs_filebd` (file-backed) | SPI flash driver |
| `hal_rng` | `/dev/urandom` | Hardware TRNG |
| `hal_log` | `fprintf(stderr)` | UART / RTT |

## Prerequisites

| Dependency | Version | Notes |
|---|---|---|
| GCC or Clang | C11 | OSM build |
| CMake | ≥ 3.16 | OSM build system |
| SDL2 | ≥ 2.0 | `libsdl2-dev` on Debian/Ubuntu |
| JDK | ≥ 17 | Companion App (desktop & Android) |
| pkg-config | any | Used by CMake to find SDL2 |
| Git | any | For submodules |
| Python | ≥ 3.10 | E2E / BLE integration tests |
| libdbus-1 | any | `libdbus-1-dev` — only for BLE transport build |

```bash
# Core (TCP simulator + Companion App + tests)
sudo apt-get install build-essential cmake libsdl2-dev pkg-config git \
    openjdk-17-jdk python3 python3-pip

# BLE transport build (optional — requires BlueZ adapter)
sudo apt-get install libdbus-1-dev

# Python test dependencies
pip install pytest pynacl                       # E2E tests
pip install bleak pytest-asyncio                # BLE integration tests (optional)
```

## License

This work is licensed under the
[Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-nc-sa/4.0/).
See [LICENSE](LICENSE) for the full text.
