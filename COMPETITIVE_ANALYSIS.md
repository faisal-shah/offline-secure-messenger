# Competitive Analysis: Offline Secure Messenger (OSM)

> **Date**: February 2026
> **Scope**: Exhaustive search for products implementing air-gapped hardware encryption over existing messaging transports

---

## Executive Summary

After extensive research across open-source repositories, commercial products, academic papers, defunct law-enforcement targets, and hardware platforms, **only one direct competitor exists worldwide**: [qryptr](https://qryptr.com). Every other product in the secure communications space either bundles its own transport (TFC, Meshtastic), is a modified phone (EncroChat, Sky ECC), or is purely software (Briar, Signal). OSM and qryptr are the only two projects that implement the same core concept: a dedicated, air-gapped hardware device that encrypts messages offline and uses existing messaging apps as a dumb ciphertext pipe.

The defunct centralized encrypted phone networks (EncroChat, Sky ECC, Phantom Secure, ANOM) validate OSM's architectural approach — they were all taken down via server compromise, a vulnerability that simply does not exist in the "bring your own transport" model.

---

## What OSM Is

The **Offline Secure Messenger** is a dedicated microcontroller-based hardware device (targeting LILYGO T-Deck: ESP32-S3, 320×240 color LCD, QWERTY keyboard) that performs all encryption, decryption, and key management on-device. Plaintext never leaves the hardware. It communicates with a **Companion App (CA)** on Android/Desktop over BLE, which acts as a clipboard bridge — the user's phone only ever sees ciphertext, which they copy/paste into their regular messaging app (Signal, WhatsApp, Telegram, email, SMS, etc.).

### Core Architecture

```
┌──────────────────┐     BLE      ┌──────────────────┐     Any App     ┌──────────────┐
│   OSM Device     │◄────────────►│  Companion App   │◄──────────────►│  Messenger   │
│                  │  (ciphertext  │  (clipboard      │   (copy/paste   │  (Signal,    │
│ • X25519 ECDH    │   only)       │   bridge only)   │    ciphertext)  │   WhatsApp,  │
│ • XSalsa20-Poly  │              │                  │                │   SMS, etc.) │
│ • TweetNaCl      │              │ Phone only sees  │                │              │
│ • Keys on device │              │ encrypted text   │                │              │
└──────────────────┘              └──────────────────┘                └──────────────┘
```

### Core Differentiators

- **Air-gapped encryption**: Crypto keys and plaintext never touch the phone or PC
- **Transport agnostic**: Uses any messaging app as a dumb ciphertext pipe
- **Dedicated hardware**: Small, cheap microcontroller with physical keyboard
- **Open source**: C + LVGL firmware, TweetNaCl (X25519 + XSalsa20-Poly1305)
- **BLE bridge**: Companion App bridges ciphertext between OSM and messaging apps
- **Text ciphertext**: Base64-encoded output works over any channel including SMS and email

---

## Competitive Landscape

### Tier 1: Direct Competitor

#### qryptr — The Only Direct Competitor

| | Details |
|---|---|
| **URL** | [qryptr.com](https://qryptr.com) / [Codeberg](https://codeberg.org/qryptr/qryptr) |
| **Hardware** | Custom PCB (mainplate + frontplate), RP2040 MCU, GM803 hardware QR scanner, Sharp LS027B7DH01 monochrome display, physical keyboard, LiPo battery |
| **Crypto** | Curve25519 ECDH + ChaChaPoly (Arduino Crypto library), 32-byte ECC keys |
| **Transport** | QR codes — device displays encrypted message as QR on its screen; user photographs QR with phone camera and sends the photo via any messenger; recipient scans QR from phone screen using device's GM803 camera |
| **Message limit** | 299 characters per message (fits in a single static QR code) |
| **Key exchange** | In-person QR code scanning only (device displays pubkey as QR, other device scans it) |
| **Status** | Active development, presented at WHY2025 (CCC conference), NLnet funded (NGI0 Commons Fund), open hardware (OSHW) with PCB designs on OSHW Lab, orderable from JLCPCB |
| **Open source** | Full hardware (Gerber, BOM, pick-and-place) + Arduino firmware |
| **Similarity** | ★★★★★ — Nearly identical concept |

**qryptr's planned improvements** (from their roadmap): RP2350 with hardware TRNG + secure boot, RF/audio shielding, switch to Monocypher, symmetric encryption on private key, group keys, deadman's switch, multiple identity support.

---

### Detailed OSM vs qryptr Comparison

The following analysis focuses on meaningful architectural and conceptual differences — not cosmetic ones like display color or UI framework.

#### 1. Ciphertext Format: Text vs Image

| | OSM | qryptr |
|---|---|---|
| **Output** | Base64 text | QR code image |
| **Works over SMS** | ✅ | ❌ |
| **Works over email body** | ✅ | ❌ (attachment only) |
| **Works over any messenger** | ✅ | ✅ (if it supports images) |
| **Printable on paper** | ✅ (text) | ✅ (QR image) |
| **Machine parseable** | ✅ (copy/paste) | Requires camera |

OSM's text ciphertext is more universally transportable. It works on every communication channel that can carry text, including SMS (which cannot carry images inline), plain email bodies, web forums, IRC, and even handwritten notes. qryptr's QR approach requires the transport to support image attachments.

#### 2. Companion App vs No App (Attack Surface Analysis)

- **OSM** requires a Companion App installed on the phone
- **qryptr** needs nothing on the phone — any camera + any messenger

Given the threat model (phone is assumed compromised), the CA only handles ciphertext, so a compromised phone cannot leak plaintext in either case. The real concern is **attack surface on the device itself**:

- **OSM risk**: A compromised phone could send malformed BLE GATT packets to try to crash or exploit the ESP32's BLE stack. BLE firmware stacks are complex and have had CVEs.
- **qryptr risk**: A crafted QR code displayed on a compromised phone could attempt to exploit a parsing bug in the GM803 QR scanner firmware. QR decoders are simpler but still process untrusted input.

Both have attack surfaces — different kinds, comparable degrees of risk. The meaningful qryptr advantage is **zero app footprint on the phone** — nothing to install, nothing detectable. An adversary examining the phone cannot find evidence of secure communication usage. OSM's CA could be designed to look innocuous (e.g., a generic "BLE clipboard" utility), but it is still an installed app.

#### 3. Message Size and Payload Capacity

| | OSM | qryptr |
|---|---|---|
| **Practical typing** | ~200-500 chars (tiny keyboard) | ~200-300 chars (tiny keyboard) |
| **Technical limit** | Unbounded (BLE fragmentation) | 299 characters (single QR) |
| **Key material exchange** | ✅ Full X25519 pubkeys + metadata | ✅ Fits in single QR |
| **Forwarding received messages** | ✅ Can forward long ciphertext | ❌ Truncated if >299 chars |
| **File/binary payloads** | ✅ (base64 encoded over BLE) | ❌ |

Both are text messengers on tiny keyboards, so users type short messages in practice. But OSM can handle longer ciphertext payloads — forwarded messages, key material with metadata, or even small file transfers — that qryptr fundamentally cannot.

#### 4. User Flow Comparison

```
SENDING:
  OSM:     Type → encrypt → [auto BLE transfer] → CA shows ciphertext → copy → paste → send
  qryptr:  Type → encrypt → QR on screen → photograph with phone → send photo
```

```
RECEIVING:
  OSM:     See ciphertext in messenger → copy → paste into CA → [auto BLE] → decrypt → read
  qryptr:  See QR image in messenger → open fullscreen → aim device camera → scan → read
```

qryptr's receive flow may be slightly smoother for the scan step (point camera at phone screen, done), though both are comparable overall. OSM's send flow is slightly smoother (automatic BLE transfer vs manually photographing the screen).

#### 5. Key Exchange: Remote-Capable vs In-Person Only

| | OSM | qryptr |
|---|---|---|
| **In-person exchange** | ✅ BLE GATT device-to-device (proposed) | ✅ QR code scan face-to-face |
| **Remote exchange** | ✅ Send pubkey via messenger (with fingerprint verification) | ❌ Must meet in person |
| **MITM resistance** | In-person: immune. Remote: depends on fingerprint verification | Immune (in-person only) |

qryptr's in-person-only model eliminates MITM entirely — but at the cost of requiring physical meetings for every new contact. OSM offers both options:

**Proposed BLE GATT in-person key exchange** (reuses existing protocol):
1. One device enters "pairing mode" — advertises as BLE peripheral using the same GATT service
2. Other device scans, finds it, connects as BLE central
3. Exchange X25519 pubkeys over existing TX/RX GATT characteristics
4. Both devices display a fingerprint hash — users confirm verbally
5. RSSI threshold enforces physical proximity (reject connections indicating >1m distance)

This uses the same open BLE GATT standard already implemented for CA communication — no new protocol stack, no proprietary dependency, works on any BLE 4.0+ hardware. Compared to qryptr's QR exchange, the BLE approach is faster (just proximity, no optical alignment needed) and includes built-in proximity enforcement.

#### 6. Companion App as a Platform

The CA is not just a clipboard bridge — it's a management and maintenance platform for the OSM device (when used from a trusted device):

| Capability | OSM (via CA) | qryptr |
|---|---|---|
| **Firmware updates** | ✅ OTA over BLE | ❌ USB/serial only |
| **Device management** | ✅ Settings, storage, status | ❌ USB/serial only |
| **Data export** | ✅ Contacts, history, key backups | ❌ USB/serial only |
| **Diagnostics** | ✅ Logs, battery, protocol stats | ❌ USB/serial only |

qryptr has no companion app — any device management requires physical USB/serial access to the RP2040. OSM's CA enables a richer device lifecycle when the user chooses to use a trusted machine.

#### 7. Desktop and Laptop Usability

| | OSM | qryptr |
|---|---|---|
| **Desktop support** | ✅ CA runs on desktop (Kotlin Multiplatform), BLE dongle, text copy/paste | ❌ Webcam QR scanning is awkward |
| **Laptop support** | ✅ Same as desktop | ❌ Fixed webcam angle, poor for QR |
| **Tablet support** | ✅ CA on Android tablet | ✅ Tablet camera works for QR |
| **Phone support** | ✅ CA on Android phone | ✅ Phone camera works for QR |

OSM's BLE + text approach works naturally across all form factors. qryptr's QR approach is designed around phone cameras — desktop/laptop webcams are typically positioned at the top of the screen at a fixed angle, making it difficult to hold a small device at the right distance and angle for reliable QR scanning. This effectively limits qryptr to phone-only use in practice.

#### 8. Hardware Availability and Form Factor

| | OSM | qryptr |
|---|---|---|
| **Current hardware** | LILYGO T-Deck (~$50, off-the-shelf) | Custom PCB (order from JLCPCB, assemble) |
| **Setup effort** | Buy device → flash firmware | Order PCBs → order components → solder/assemble |
| **Display** | 320×240 color LCD | Sharp monochrome memory display |
| **Future vision** | Custom slim hardware (phone wallet/case form factor) | RP2350 upgrade, RF shielding |

OSM's use of off-the-shelf hardware dramatically lowers the barrier to entry for new users. qryptr's custom PCB approach gives them hardware optimization (dedicated QR scanner module, power-efficient display) but requires electronics assembly skills.

#### 9. Summary: Trade-offs That Matter

| Capability | OSM | qryptr |
|---|---|---|
| Ciphertext is text (universal transport) | ✅ | ❌ (images) |
| No app on phone (zero footprint) | ❌ | ✅ |
| Longer messages / key payloads | ✅ | ❌ (299 char cap) |
| In-person key exchange (no MITM) | ✅ (BLE GATT device-to-device) | ✅ (QR scan) |
| Remote key exchange option | ✅ | ❌ |
| Device-to-device direct (no phone) | ✅ (BLE) | ❌ |
| Desktop/laptop friendly | ✅ (BLE + text paste) | ❌ (webcam QR awkward) |
| Device management / firmware update | ✅ (via CA on trusted device) | ❌ (USB/serial only) |
| Off-the-shelf hardware (low barrier) | ✅ (T-Deck) | ❌ (custom PCB assembly) |
| Zero wireless emissions | ❌ (BLE radio) | ✅ (optical only) |
| No companion app to install | ❌ | ✅ |

**Neither is strictly superior.** They make fundamentally different trade-offs around the same core concept. OSM optimizes for versatility (text transport, BLE management, desktop support, remote key exchange). qryptr optimizes for minimal footprint (no app, no radio emissions, no wireless attack surface).

---

### Tier 2: Related but Architecturally Different (Not Direct Competitors)

These products share some philosophy with OSM but solve fundamentally different problems or use different architectures.

#### Tinfoil Chat (TFC)

| | Details |
|---|---|
| **URL** | [github.com/maqp/tfc](https://github.com/maqp/tfc) |
| **Architecture** | Three-computer system (Source, Networked, Destination) with hardware data diodes |
| **Transport** | Its own Tor onion service network |
| **Crypto** | XChaCha20-Poly1305, X448, BLAKE2b |
| **Open source** | Yes (Python) |
| **Similarity** | ★★☆☆☆ |

**Why NOT a competitor**: TFC has its own transport layer (Tor onion services). It does NOT use existing messengers as a ciphertext pipe. The networked computer runs Tor relay software — it's not a "dumb transport" model. Anyone can already use Tor from their phone. TFC's value proposition is the hardware data diode isolation between three dedicated Linux computers, which is a completely different form factor and use case from a pocketable device. It shares the philosophy of "keys off the networked device" but the architecture is incompatible with casual or mobile use.

#### EncroChat (defunct, 2020)

| | Details |
|---|---|
| **Hardware** | Modified Android phones with disabled GPS/camera/mic/USB |
| **Transport** | Proprietary encrypted network (closed ecosystem) |
| **Takedown** | Infiltrated by French/Dutch law enforcement via server compromise |
| **Similarity** | ★★★☆☆ |

Dedicated encrypted messaging hardware, but phone-based (not air-gapped) and operated its own centralized network. The centralized server model was its fatal weakness — law enforcement compromised the servers and pushed malware to all devices.

#### Sky ECC (defunct, 2021)

| | Details |
|---|---|
| **Hardware** | Modified BlackBerry/Android devices |
| **Transport** | Proprietary encrypted network |
| **Takedown** | Dismantled by Belgian/French/Dutch law enforcement via server access |
| **Similarity** | ★★★☆☆ |

Same category as EncroChat — dedicated crypto messaging device with centralized network. Same failure mode: server compromise gave law enforcement access to all communications.

#### Phantom Secure (defunct, 2018)

| | Details |
|---|---|
| **Hardware** | Modified BlackBerry phones (stripped cameras, mics, GPS) |
| **Transport** | Proprietary encrypted network |
| **Takedown** | CEO arrested, servers seized |
| **Similarity** | ★★☆☆☆ |

Hardware modification approach, but fundamentally different from OSM — it was a modified consumer phone, not a purpose-built MCU device. Centralized infrastructure was its downfall.

#### ANOM (FBI honeypot, revealed 2021)

| | Details |
|---|---|
| **Hardware** | Modified Android devices secretly distributed by the FBI |
| **Transport** | Messages silently copied to FBI servers |
| **Similarity** | ★☆☆☆☆ |

A sting operation, not a real product. Demonstrates that users of closed-source encrypted phone networks cannot verify trustworthiness. OSM's open-source firmware directly addresses this — every line of code is auditable.

#### GSMK CryptoPhone 600G

| | Details |
|---|---|
| **URL** | [cryptophone.de](https://www.cryptophone.de) |
| **Hardware** | Hardened Android phone with tamper-resistant hardware, TPM, baseband firewall |
| **Crypto** | AES-256, 4096-bit DH key exchange |
| **Certifications** | FIPS 140-2, Common Criteria, NSA CSfC |
| **Price** | Enterprise/government ($$$$) |
| **Similarity** | ★★☆☆☆ |

A full smartphone with its own network connectivity — not an air-gapped companion device. Targets enterprise and government customers with compliance requirements. Completely different market, form factor, and price point from OSM.

#### BlackBerry SecuSUITE

| | Details |
|---|---|
| **URL** | [blackberry.com/secure-communications](https://www.blackberry.com/en/secure-communications/secusuite) |
| **Certifications** | NSA CSfC, NATO Restricted, EAL4+ |
| **Similarity** | ★★☆☆☆ |

Software solution running on standard Android/iOS phones. Enterprise/government market. No air gap — the phone processes plaintext.

#### KoolSpan TrustCall + TrustChip

| | Details |
|---|---|
| **URL** | [koolspan.com](https://www.koolspan.com) |
| **Hardware** | microSD crypto chip ("TrustChip") + phone sleeve for iPhone |
| **Crypto** | AES-256, FIPS 140-2 certified hardware module |
| **Similarity** | ★★★☆☆ |

An interesting parallel: a separate hardware crypto module that plugs into a phone. But it's a chip accessory, not a standalone device with its own display and keyboard. The phone still handles plaintext display and input. The crypto module only offloads key storage and crypto operations.

---

### Tier 3: Related Software (No Dedicated Hardware)

#### Briar Messenger

| | Details |
|---|---|
| **URL** | [briarproject.org](https://briarproject.org) |
| **Platform** | Android app (desktop beta) |
| **Transport** | Bluetooth, Wi-Fi Direct, or Tor |
| **Similarity** | ★★☆☆☆ |

Shares the offline/peer-to-peer messaging philosophy and can work without internet via Bluetooth. But it's purely software on the phone — no air gap. The phone holds keys and plaintext, which is the exact vulnerability OSM addresses.

#### Signal / WhatsApp / Matrix

| | Details |
|---|---|
| **Status** | Mainstream end-to-end encrypted messaging apps |
| **Similarity** | ★☆☆☆☆ |

OSM literally uses these as transport pipes. They provide E2EE but the phone still holds keys and plaintext. If the phone is compromised (malware, OS exploit, state-level spyware like Pegasus), the messages are exposed regardless of transport encryption. This is the exact vulnerability that motivates OSM's existence.

---

### Tier 4: Hardware Platforms (Same Hardware, Different Purpose)

These projects run on the same hardware as OSM but solve transport problems, not endpoint security.

#### Meshtastic

| | Details |
|---|---|
| **URL** | [meshtastic.org](https://meshtastic.org) |
| **Hardware** | LILYGO T-Deck, T-Beam, Heltec, RAK, etc. |
| **Transport** | LoRa mesh radio (no internet, no phone needed) |
| **Similarity** | ★★☆☆☆ |

Runs on the same T-Deck hardware but is a completely different product. Meshtastic IS the transport (LoRa radio mesh). OSM is transport-agnostic and relies on existing messengers. Meshtastic doesn't air-gap from the phone — Bluetooth pairing shows plaintext in the companion app. These are complementary, not competing — in theory, one could use Meshtastic as a transport for OSM ciphertext.

#### ezOS

| | Details |
|---|---|
| **URL** | [github.com/ezmesh/ezos](https://github.com/ezmesh/ezos) |
| **Hardware** | LILYGO T-Deck Plus |
| **Similarity** | ★★☆☆☆ |

Secure LoRa mesh with AES-256-GCM + Ed25519, group chat, GPS. Same hardware, different transport model. Not air-gapped from phone.

#### Reticulum

| | Details |
|---|---|
| **URL** | [github.com/markqvist/Reticulum](https://github.com/markqvist/Reticulum) |
| **Similarity** | ★★☆☆☆ |

Encrypted off-grid networking protocol stack with active discussion about T-Deck ports. Again, a transport solution — not an endpoint security solution.

---

### Tier 5: Secure Phones (Privacy-Focused but Not Air-Gapped)

#### Purism Librem 5

| | Details |
|---|---|
| **URL** | [puri.sm](https://puri.sm) |
| **Features** | Hardware kill switches, PureOS (Linux), open hardware schematics |
| **Similarity** | ★☆☆☆☆ |

Privacy-focused phone with hardware kill switches. But it IS the phone — if compromised, plaintext is exposed. Not an air-gapped companion device.

#### Pine64 PinePhone

| | Details |
|---|---|
| **URL** | [pine64.org](https://pine64.org/devices/pinephone) |
| **Features** | Hardware kill switches, open source, multiple Linux OS options |
| **Similarity** | ★☆☆☆☆ |

Same as Librem 5 — a privacy phone, not an air-gapped companion device. If the phone OS is compromised, the encryption keys are compromised.

---

## Competitive Positioning Matrix

```
                          Air-Gapped    Uses Existing   Dedicated   Open     Portable /
                          Crypto        Messengers      Hardware    Source   Pocketable
────────────────────────────────────────────────────────────────────────────────────────
OSM                         ✅              ✅             ✅         ✅        ✅
qryptr                      ✅              ✅             ✅         ✅        ✅
TFC                         ✅              ❌ (Tor)       ✅         ✅        ❌ (3 PCs)
EncroChat (†)               ❌              ❌             ✅         ❌        ✅
Sky ECC (†)                 ❌              ❌             ✅         ❌        ✅
Phantom Secure (†)          ❌              ❌             ✅         ❌        ✅
GSMK CryptoPhone            ❌              ❌             ✅         ❌        ✅
KoolSpan TrustChip           ✅ (partial)   ❌             ✅         ❌        ✅
Briar                        ❌              ❌             ❌         ✅        ✅
Meshtastic                   ❌              ❌             ✅         ✅        ✅
Signal / Matrix              ❌              N/A            ❌         ✅        ✅
```

**(†) = defunct / dismantled by law enforcement**

**Only OSM and qryptr check all five boxes.**

---

## Key Findings

### 1. qryptr Is the Only Direct Competitor Found Worldwide

After exhaustive searching across GitHub, Codeberg, commercial product databases, academic papers, security conferences, and hardware project registries, **qryptr is the only product in the world that implements the same concept**: a dedicated, air-gapped hardware encryption device that uses existing messaging apps as a dumb ciphertext transport.

A [Nym hackathon proposal](https://github.com/nym-hackathon/ideas/issues/9) described this concept but was never built — it remains an idea. No other implementations were found anywhere.

### 2. This Is a Genuinely Novel Product Category

The "hardware crypto wallet for messaging" pattern (air-gapped device handles crypto, phone broadcasts ciphertext) is analogous to cryptocurrency hardware wallets (Ledger, Trezor — air-gapped device signs transactions, phone broadcasts them). But nobody has applied this proven pattern to messaging except OSM and qryptr. This represents a largely unoccupied market niche.

### 3. The EncroChat / Sky ECC / Phantom Secure Failures Validate This Architecture

All three centralized encrypted phone networks were taken down because law enforcement compromised their servers. Key lessons:

- **Centralized servers are a single point of failure** — OSM has no servers at all
- **Closed-source firmware enables hidden backdoors** (ANOM was literally an FBI honeypot) — OSM is fully open source
- **Modified phones are still phones** — if the OS is compromised, keys are exposed. OSM's MCU runs bare-metal firmware with no general-purpose OS to exploit
- **"Bring your own transport" eliminates the network as an attack vector** — there is no OSM network to infiltrate

### 4. The T-Deck Ecosystem Is Complementary, Not Competitive

Meshtastic, ezOS, and Reticulum all target the same T-Deck hardware but solve a different problem: transport (how to get messages across distance without internet). OSM solves endpoint security (how to keep keys off compromised devices). In theory, these are stackable — one could use Meshtastic as a transport for OSM ciphertext.

### 5. OSM and qryptr Make Different but Equally Valid Trade-offs

Neither product is strictly superior. They represent two philosophies applied to the same concept:

- **OSM**: Optimizes for **versatility** — text ciphertext (universal transport), BLE device management, desktop/laptop support, remote key exchange, unlimited message size, companion app as a platform
- **qryptr**: Optimizes for **minimal footprint** — no app needed (zero phone evidence), no radio emissions (optical only), no wireless attack surface, simpler threat model

---

## Recommendations

### For Product Development

1. **Study qryptr deeply** — acquire or build one to understand the UX firsthand. It's the only benchmark that matters.

2. **Implement BLE GATT in-person key exchange** — this gives OSM both in-person security (eliminates MITM) and remote convenience, while qryptr is limited to in-person only. Reuse the existing BLE GATT protocol — no new stack needed.

3. **Consider adding a QR code mode** — for users who want absolute air-gap purity (no BLE radio emissions at all), offer an optional QR display/scan mode. This would make OSM a superset of qryptr's capabilities.

4. **Leverage the Companion App as a platform** — firmware updates, device management, data export, and diagnostics via BLE are capabilities qryptr fundamentally cannot offer. This is a genuine competitive advantage when users have access to a trusted device.

5. **Emphasize desktop/laptop support** — OSM's BLE + text approach works seamlessly on desktops and laptops where qryptr's QR camera approach is impractical. This expands the addressable user base significantly.

### For Positioning and Marketing

6. **Document the threat model explicitly** — compare against EncroChat/Sky ECC centralized failures and explain why "bring your own transport" is architecturally immune to their failure mode.

7. **Frame OSM as "hardware wallet for messaging"** — the crypto wallet analogy (Ledger/Trezor) is immediately understandable to security-conscious audiences and accurately describes the architecture.

8. **Off-the-shelf hardware is an advantage** — LILYGO T-Deck can be purchased ready-made for ~$50 and flashed immediately. qryptr requires ordering custom PCBs from JLCPCB and soldering/assembly. This dramatically lowers the barrier to entry.

### For Funding and Community

9. **Consider NLnet / NGI0 funding** — qryptr received EU funding through this program. OSM could apply to the same grants.

10. **Engage the security conference circuit** — qryptr was presented at WHY2025 (CCC conference). OSM should target similar venues (CCC, DEF CON, FOSDEM) for visibility in the privacy/security community.
