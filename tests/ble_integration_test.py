# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "bleak",
#     "pytest",
#     "pytest-asyncio",
# ]
# ///
"""
BLE Integration Test for the OSM GATT Server.

Tests the OSM's BLE GATT service by acting as a GATT client via bleak:
  1. Scan for the OSM device by service UUID
  2. Connect and discover services
  3. Read the INFO characteristic (device name)
  4. Subscribe to TX notifications
  5. Write a fragment to RX and verify ACK via TX notification
  6. Disconnect and reconnect

Requirements:
  - OSM built with BLE transport: cmake .. -DTRANSPORT_BLE=ON && make
  - OSM running as a BLE peripheral
  - A BLE adapter available on the test machine

Usage:
    uv run tests/ble_integration_test.py           # standalone
    uv run pytest tests/ble_integration_test.py -v  # via pytest
"""

import asyncio
import hashlib
import struct
import sys

import pytest
import pytest_asyncio
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakDBusError, BleakError

# GATT UUIDs (must match transport_ble.c / transport.h)
SERVICE_UUID = "0000fe00-0000-1000-8000-00805f9b34fb"
TX_CHAR_UUID = "0000fe02-0000-1000-8000-00805f9b34fb"
RX_CHAR_UUID = "0000fe03-0000-1000-8000-00805f9b34fb"
INFO_CHAR_UUID = "0000fe05-0000-1000-8000-00805f9b34fb"

# Fragmentation constants (must match transport.h)
FRAG_FLAG_START = 0x01
FRAG_FLAG_END = 0x02
FRAG_FLAG_ACK = 0x04
ACK_ID_LEN = 8

SCAN_TIMEOUT = 10.0  # seconds to scan for the OSM device
NOTIFY_TIMEOUT = 5.0  # seconds to wait for a TX notification


def compute_msg_id(data: bytes) -> bytes:
    """First 8 bytes of SHA-512, matching TweetNaCl's crypto_hash."""
    return hashlib.sha512(data).digest()[:ACK_ID_LEN]


def build_single_fragment(payload: bytes) -> bytes:
    """Build a START+END fragment for a short payload.

    Wire format (little-endian):
        [flags:1][seq:2][total_len:2][payload:N]
    The 2-byte total_len field is present only in the START fragment.
    """
    flags = FRAG_FLAG_START | FRAG_FLAG_END
    seq = 0
    total_len = len(payload)
    header = struct.pack("<BH", flags, seq)
    length_prefix = struct.pack("<H", total_len)
    return header + length_prefix + payload


def _ble_adapter_available() -> bool:
    """Check whether a BLE adapter is usable (best-effort)."""
    try:
        loop = asyncio.new_event_loop()
        adapters = loop.run_until_complete(BleakScanner.discover(timeout=0.5))
        loop.close()
        return True
    except (BleakError, BleakDBusError, OSError, PermissionError):
        return False
    except Exception:
        return False


# Skip the entire module if no BLE adapter is detected
ble_available = _ble_adapter_available()
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(not ble_available, reason="No BLE adapter available"),
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def osm_device():
    """Scan for the OSM BLE peripheral and return its BLEDevice."""
    print(f"\n🔍 Scanning for OSM service {SERVICE_UUID} …")
    device = await BleakScanner.find_device_by_filter(
        lambda _dev, adv: SERVICE_UUID.lower() in [
            u.lower() for u in (adv.service_uuids or [])
        ],
        timeout=SCAN_TIMEOUT,
    )
    if device is None:
        pytest.skip("OSM BLE device not found within scan timeout")
    print(f"✅ Found OSM device: {device.name} [{device.address}]")
    return device


@pytest_asyncio.fixture
async def osm_client(osm_device):
    """Connect to the OSM and yield a BleakClient; disconnect on teardown."""
    client = BleakClient(osm_device)
    print(f"🔗 Connecting to {osm_device.address} …")
    await client.connect()
    print("✅ Connected — discovering services …")
    yield client
    if client.is_connected:
        await client.disconnect()
        print("🔌 Disconnected (teardown)")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBLEGATT:
    """Integration tests against a live OSM BLE GATT server."""

    async def test_discover_services(self, osm_client: BleakClient):
        """Service discovery should expose our custom GATT service."""
        services = osm_client.services
        svc = services.get_service(SERVICE_UUID)
        assert svc is not None, f"Service {SERVICE_UUID} not found"
        print(f"✅ Service discovered: {svc.uuid}")

        uuids = [c.uuid for c in svc.characteristics]
        assert TX_CHAR_UUID in uuids, "TX characteristic missing"
        assert RX_CHAR_UUID in uuids, "RX characteristic missing"
        assert INFO_CHAR_UUID in uuids, "INFO characteristic missing"
        print(f"   Characteristics: {uuids}")

    async def test_read_info(self, osm_client: BleakClient):
        """INFO characteristic should return a non-empty device name."""
        data = await osm_client.read_gatt_char(INFO_CHAR_UUID)
        assert data is not None and len(data) > 0, "INFO returned empty data"
        name = data.decode("utf-8", errors="replace")
        print(f"✅ INFO characteristic value: '{name}'")
        assert len(name) > 0, "Device name is empty"

    async def test_tx_notify_and_rx_write(self, osm_client: BleakClient):
        """Write a fragment to RX and expect an ACK notification on TX."""
        notifications: list[bytearray] = []
        event = asyncio.Event()

        def on_notify(_sender, data: bytearray):
            print(f"📨 TX notification: {data.hex()}")
            notifications.append(data)
            event.set()

        # Subscribe to TX notifications
        print("📡 Subscribing to TX notifications …")
        await osm_client.start_notify(TX_CHAR_UUID, on_notify)

        # Build and write a single-fragment message to RX
        payload = b"Hello BLE"
        fragment = build_single_fragment(payload)
        print(f"📤 Writing fragment to RX ({len(fragment)} bytes): {fragment.hex()}")
        await osm_client.write_gatt_char(RX_CHAR_UUID, fragment, response=False)

        # Wait for the ACK notification
        try:
            await asyncio.wait_for(event.wait(), timeout=NOTIFY_TIMEOUT)
        except asyncio.TimeoutError:
            pytest.fail("Timed out waiting for TX notification (ACK)")

        assert len(notifications) > 0, "No TX notification received"

        # Verify the ACK structure: flags=ACK, seq=0, then 8-byte msg_id
        ack = bytes(notifications[0])
        assert len(ack) >= 3 + ACK_ID_LEN, f"ACK too short: {len(ack)} bytes"
        flags = ack[0]
        assert flags & FRAG_FLAG_ACK, f"Expected ACK flag, got flags=0x{flags:02x}"
        expected_id = compute_msg_id(payload)
        actual_id = ack[3 : 3 + ACK_ID_LEN]
        assert actual_id == expected_id, (
            f"ACK msg_id mismatch: expected {expected_id.hex()}, got {actual_id.hex()}"
        )
        print(f"✅ ACK received with correct msg_id: {actual_id.hex()}")

        await osm_client.stop_notify(TX_CHAR_UUID)

    async def test_disconnect_reconnect(self, osm_device, osm_client: BleakClient):
        """Disconnect and reconnect should succeed cleanly."""
        addr = osm_device.address
        print(f"🔌 Disconnecting from {addr} …")
        await osm_client.disconnect()
        assert not osm_client.is_connected
        print("✅ Disconnected")

        await asyncio.sleep(1.0)  # brief pause before reconnect

        print(f"🔗 Reconnecting to {addr} …")
        await osm_client.connect()
        assert osm_client.is_connected
        print("✅ Reconnected successfully")

        # Verify we can still read INFO after reconnect
        data = await osm_client.read_gatt_char(INFO_CHAR_UUID)
        assert data is not None and len(data) > 0
        print(f"✅ INFO after reconnect: '{data.decode('utf-8', errors='replace')}'")


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "-s"]))
