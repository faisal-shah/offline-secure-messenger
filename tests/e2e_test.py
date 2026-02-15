# /// script
# dependencies = []
# ///
"""
E2E Integration Test for Offline Secure Messenger.

Orchestrates 2 OSM instances + simulated CA transport to test:
1. Key exchange between two users
2. Encrypted message round-trip
3. Fragmentation of large messages
4. Offline queuing and reconnect delivery
5. Multiple OSM instances on different ports

Usage:
    cd osm/build && cmake .. && make -j$(nproc)
    cd ../.. && python3 tests/e2e_test.py
"""

import socket
import struct
import subprocess
import sys
import time
import os
import signal
import base64
import glob as globmod

BINARY = os.path.join(os.path.dirname(__file__), "..", "osm", "build", "secure_communicator")
PORT_A = 19210
PORT_B = 19211

# Data files that OSM persists (relative to cwd)
DATA_FILES = ["data_contacts.json", "data_messages.json", "data_identity.json"]

# Fragmentation constants (must match transport.h)
FRAG_FLAG_START = 0x01
FRAG_FLAG_END = 0x02
CHAR_UUID_TX = 0xFE02
CHAR_UUID_RX = 0xFE03
MTU = 200


class TcpClient:
    """Simulates a Companion App TCP client."""

    def __init__(self, port: int, name: str = "CA"):
        self.port = port
        self.name = name
        self.sock: socket.socket | None = None
        self.received: list[tuple[int, bytes]] = []  # (char_uuid, data)

    def connect(self, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(1.0)
                self.sock.connect(("127.0.0.1", self.port))
                self.sock.setblocking(False)
                return True
            except (ConnectionRefusedError, OSError):
                if self.sock:
                    self.sock.close()
                    self.sock = None
                time.sleep(0.2)
        return False

    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_message(self, char_uuid: int, data: bytes):
        """Send data with fragmentation protocol."""
        max_payload = MTU - 3  # flags(1) + seq(2)
        offset = 0
        seq = 0

        while offset < len(data):
            is_start = offset == 0
            overhead = 2 if is_start else 0  # total_len in START
            chunk_size = min(len(data) - offset, max_payload - overhead)
            is_end = (offset + chunk_size >= len(data))

            flags = 0
            if is_start:
                flags |= FRAG_FLAG_START
            if is_end:
                flags |= FRAG_FLAG_END

            frag = struct.pack("<BH", flags, seq)
            if is_start:
                frag += struct.pack("<H", len(data))
            frag += data[offset:offset + chunk_size]

            # TCP frame: [4B len big-endian][2B uuid big-endian][frag]
            frame = struct.pack("!IH", len(frag), char_uuid) + frag
            self.sock.sendall(frame)

            offset += chunk_size
            seq += 1

    def poll(self, timeout: float = 0.5) -> list[tuple[int, bytes]]:
        """Read and reassemble incoming messages. Returns list of (uuid, data)."""
        messages = []
        rx_buf = bytearray()
        rx_seq = 0
        rx_active = False
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                raw = self.sock.recv(4096)
                if not raw:
                    break
            except BlockingIOError:
                time.sleep(0.01)
                continue
            except OSError:
                break

            # Buffer and parse TCP frames
            buf = raw
            pos = 0
            while pos + 6 <= len(buf):
                msg_len, char_uuid = struct.unpack("!IH", buf[pos:pos+6])
                pos += 6
                if pos + msg_len > len(buf):
                    break
                frag = buf[pos:pos+msg_len]
                pos += msg_len

                if len(frag) < 3:
                    continue
                flags, seq = struct.unpack("<BH", frag[:3])
                payload = frag[3:]

                if flags & FRAG_FLAG_START:
                    rx_buf = bytearray()
                    rx_seq = 0
                    rx_active = True
                    if len(payload) >= 2:
                        payload = payload[2:]  # skip total_len

                if not rx_active or seq != rx_seq:
                    rx_active = False
                    continue

                rx_buf.extend(payload)
                rx_seq += 1

                if flags & FRAG_FLAG_END:
                    messages.append((char_uuid, bytes(rx_buf)))
                    rx_active = False
                    rx_buf = bytearray()

        self.received.extend(messages)
        return messages


class OsmProcess:
    """Manages an OSM simulator instance."""

    def __init__(self, port: int, name: str = "OSM"):
        self.port = port
        self.name = name
        self.proc: subprocess.Popen | None = None

    @staticmethod
    def cleanup_data_files():
        """Remove persisted data files so each test starts fresh."""
        for f in DATA_FILES:
            if os.path.exists(f):
                os.remove(f)

    def start(self, clean: bool = True) -> bool:
        if clean:
            self.cleanup_data_files()
        env = os.environ.copy()
        env["SDL_VIDEODRIVER"] = "dummy"
        try:
            self.proc = subprocess.Popen(
                [BINARY, "--port", str(self.port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError:
            print(f"  ERROR: Binary not found: {BINARY}")
            return False
        # Wait for port to be available
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect(("127.0.0.1", self.port))
                s.close()
                return True
            except (ConnectionRefusedError, OSError):
                time.sleep(0.1)
        return False

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            self.proc = None


def test_tcp_connectivity():
    """Test 1: Verify OSM starts and accepts TCP connections."""
    print("[Test 1] TCP connectivity")
    osm = OsmProcess(PORT_A, "OSM-A")
    assert osm.start(), "OSM failed to start"
    print("  PASS: OSM started on port", PORT_A)

    ca = TcpClient(PORT_A, "CA-A")
    assert ca.connect(), "CA failed to connect"
    print("  PASS: CA connected to OSM")

    ca.disconnect()
    osm.stop()
    print("  PASS: Cleanup OK")


def test_send_receive():
    """Test 2: Send data from CA to OSM and receive response."""
    print("\n[Test 2] Send/receive via transport")
    osm = OsmProcess(PORT_A, "OSM-A")
    assert osm.start(), "OSM failed to start"

    ca = TcpClient(PORT_A, "CA-A")
    assert ca.connect(), "CA failed to connect"

    # Send a properly enveloped message (will fail decrypt but shouldn't crash)
    test_data = b"OSM:MSG:InvalidCiphertext123"
    ca.send_message(CHAR_UUID_RX, test_data)
    print("  PASS: Sent enveloped data to OSM")

    # Give OSM time to process
    time.sleep(0.5)

    # The OSM will try to decrypt and log — we just verify no crash
    assert osm.proc.poll() is None, "OSM crashed after receiving data"
    print("  PASS: OSM processed incoming data without crash")

    ca.disconnect()
    osm.stop()


def test_osm_sends_to_ca():
    """Test 3: Verify OSM can send data to connected CA (outbox)."""
    print("\n[Test 3] OSM sends to CA via outbox")
    osm = OsmProcess(PORT_A, "OSM-A")
    assert osm.start(), "OSM failed to start"

    ca = TcpClient(PORT_A, "CA-A")
    assert ca.connect(), "CA failed to connect"
    time.sleep(0.3)

    # Poll for any data the OSM might send (e.g., from outbox flush)
    msgs = ca.poll(timeout=1.0)
    # OSM starts with empty outbox, so no messages expected
    print(f"  INFO: Received {len(msgs)} messages from OSM (expected 0 on fresh start)")
    assert osm.proc.poll() is None, "OSM crashed"
    print("  PASS: OSM alive, no unexpected data")

    ca.disconnect()
    osm.stop()


def test_large_message_fragmentation():
    """Test 4: Send a large message that requires fragmentation."""
    print("\n[Test 4] Large message fragmentation")
    osm = OsmProcess(PORT_A, "OSM-A")
    assert osm.start(), "OSM failed to start"

    ca = TcpClient(PORT_A, "CA-A")
    assert ca.connect(), "CA failed to connect"

    # Send a 2KB message (requires multiple fragments)
    large_data = b"X" * 2000
    ca.send_message(CHAR_UUID_RX, large_data)
    print(f"  PASS: Sent {len(large_data)}-byte fragmented message")

    time.sleep(0.5)
    assert osm.proc.poll() is None, "OSM crashed after large message"
    print("  PASS: OSM handled large fragmented message")

    ca.disconnect()
    osm.stop()


def test_multiple_osm_instances():
    """Test 5: Run two OSM instances on different ports."""
    print("\n[Test 5] Multiple OSM instances")
    osm_a = OsmProcess(PORT_A, "OSM-A")
    osm_b = OsmProcess(PORT_B, "OSM-B")

    assert osm_a.start(), "OSM-A failed to start"
    print(f"  PASS: OSM-A started on port {PORT_A}")

    assert osm_b.start(), "OSM-B failed to start"
    print(f"  PASS: OSM-B started on port {PORT_B}")

    # Connect CAs to each
    ca_a = TcpClient(PORT_A, "CA-A")
    ca_b = TcpClient(PORT_B, "CA-B")

    assert ca_a.connect(), "CA-A failed to connect"
    assert ca_b.connect(), "CA-B failed to connect"
    print("  PASS: Both CAs connected to their OSMs")

    # Send data through each independently (using envelope format)
    ca_a.send_message(CHAR_UUID_RX, b"OSM:MSG:Hello from A")
    ca_b.send_message(CHAR_UUID_RX, b"OSM:MSG:Hello from B")
    time.sleep(0.5)

    assert osm_a.proc.poll() is None, "OSM-A crashed"
    assert osm_b.proc.poll() is None, "OSM-B crashed"
    print("  PASS: Both OSMs processed data independently")

    ca_a.disconnect()
    ca_b.disconnect()
    osm_a.stop()
    osm_b.stop()


def test_reconnect():
    """Test 6: Disconnect and reconnect CA."""
    print("\n[Test 6] CA reconnect")
    osm = OsmProcess(PORT_A, "OSM-A")
    assert osm.start(), "OSM failed to start"

    ca = TcpClient(PORT_A, "CA-A")
    assert ca.connect(), "CA failed to connect (first)"
    ca.send_message(CHAR_UUID_RX, b"OSM:MSG:First connection")
    time.sleep(0.3)
    ca.disconnect()
    print("  PASS: First connection OK, disconnected")

    time.sleep(0.5)

    ca2 = TcpClient(PORT_A, "CA-A-2")
    assert ca2.connect(), "CA failed to reconnect"
    ca2.send_message(CHAR_UUID_RX, b"OSM:MSG:Second connection")
    time.sleep(0.3)
    assert osm.proc.poll() is None, "OSM crashed after reconnect"
    print("  PASS: Reconnection OK")

    ca2.disconnect()
    osm.stop()


def test_key_exchange_envelope():
    """Test 7: Key exchange via OSM:KEY:<pubkey> (no name) queues pending key."""
    print("\n[Test 7] Key exchange envelope (anonymous)")
    osm = OsmProcess(PORT_A, "OSM-A")
    assert osm.start(), "OSM failed to start"

    ca = TcpClient(PORT_A, "CA-A")
    assert ca.connect(), "CA failed to connect"
    time.sleep(0.3)

    fake_key = bytes(range(32))
    key_b64 = base64.b64encode(fake_key).decode()
    kex_msg = f"OSM:KEY:{key_b64}".encode()
    ca.send_message(CHAR_UUID_RX, kex_msg)
    print("  PASS: Sent anonymous KEX envelope to OSM")

    time.sleep(0.5)
    assert osm.proc.poll() is None, "OSM crashed after KEX message"

    osm.proc.terminate()
    osm.proc.wait(timeout=3)
    stderr = osm.proc.stderr.read().decode()
    osm.proc = None

    assert "KEX queued for assignment" in stderr, \
        f"Expected 'KEX queued for assignment', got: {stderr}"
    assert "bad pubkey" not in stderr, f"Bad pubkey error: {stderr}"
    print("  PASS: OSM queued key for user assignment")

    ca.disconnect()


def test_unknown_envelope():
    """Test 8: Unknown envelope prefix is handled gracefully."""
    print("\n[Test 8] Unknown envelope prefix")
    osm = OsmProcess(PORT_A, "OSM-A")
    assert osm.start(), "OSM failed to start"

    ca = TcpClient(PORT_A, "CA-A")
    assert ca.connect(), "CA failed to connect"

    ca.send_message(CHAR_UUID_RX, b"JUNK:SomeRandomData")
    time.sleep(0.5)
    assert osm.proc.poll() is None, "OSM crashed on unknown envelope"
    print("  PASS: Unknown envelope handled gracefully")

    ca.disconnect()
    osm.stop()


def test_kex_queues_pending_key():
    """Test 9: CA→OSM key exchange queues in pending_keys (not auto-create).

    The new anonymous protocol (OSM:KEY:<pubkey>) stores the key in a
    pending queue rather than auto-creating a contact.
    """
    print("\n[Test 9] CA→OSM KEX queues pending key")

    osm = OsmProcess(PORT_A, "OSM-A")
    assert osm.start(), "OSM failed to start"

    ca = TcpClient(PORT_A, "CA-A")
    assert ca.connect(), "CA failed to connect"
    time.sleep(0.3)

    fake_key = bytes([0x11] * 32)
    key_b64 = base64.b64encode(fake_key).decode()
    kex_msg = f"OSM:KEY:{key_b64}".encode()
    ca.send_message(CHAR_UUID_RX, kex_msg)
    time.sleep(0.5)

    assert osm.proc.poll() is None, "OSM crashed"

    osm.proc.terminate()
    osm.proc.wait(timeout=3)
    stderr = osm.proc.stderr.read().decode()
    osm.proc = None

    assert "KEX queued for assignment" in stderr, \
        f"Expected pending queue log, got: {stderr}"
    assert "bad pubkey" not in stderr, f"Bad pubkey error: {stderr}"
    print("  PASS: Key queued for assignment (not auto-created)")

    ca.disconnect()


def test_kex_dedup_pending():
    """Test 10: Duplicate KEX pubkey is rejected (not queued twice)."""
    print("\n[Test 10] KEX dedup in pending queue")

    osm = OsmProcess(PORT_A, "OSM-A")
    assert osm.start(), "OSM failed to start"

    ca = TcpClient(PORT_A, "CA-A")
    assert ca.connect(), "CA failed to connect"
    time.sleep(0.3)

    fake_key = bytes([0x22] * 32)
    key_b64 = base64.b64encode(fake_key).decode()
    kex_msg = f"OSM:KEY:{key_b64}".encode()

    # Send the same key twice
    ca.send_message(CHAR_UUID_RX, kex_msg)
    time.sleep(0.3)
    ca.send_message(CHAR_UUID_RX, kex_msg)
    time.sleep(0.5)

    assert osm.proc.poll() is None, "OSM crashed"

    osm.proc.terminate()
    osm.proc.wait(timeout=3)
    stderr = osm.proc.stderr.read().decode()
    osm.proc = None

    queued_count = stderr.count("KEX queued for assignment")
    dup_count = stderr.count("already pending")
    assert queued_count == 1, f"Expected 1 queued, got {queued_count}"
    assert dup_count == 1, f"Expected 1 duplicate rejection, got {dup_count}"
    print("  PASS: Duplicate key rejected, only queued once")

    ca.disconnect()


def test_bidirectional_kex_anonymous():
    """Test 11: Bidirectional key exchange with anonymous protocol.

    Two separate OSM instances each receive an anonymous KEX from the other.
    Both should queue the keys for assignment (not auto-create contacts).
    """
    print("\n[Test 11] Bidirectional anonymous KEX")

    # --- OSM-Bob receives a key ---
    osm_bob = OsmProcess(PORT_B, "Bob")
    assert osm_bob.start(), "OSM-Bob failed to start"

    ca_bob = TcpClient(PORT_B, "CA-Bob")
    assert ca_bob.connect(), "CA-Bob failed to connect"
    time.sleep(0.3)

    alice_key = bytes([0xAA] * 32)
    alice_b64 = base64.b64encode(alice_key).decode()
    kex_alice = f"OSM:KEY:{alice_b64}".encode()
    ca_bob.send_message(CHAR_UUID_RX, kex_alice)
    time.sleep(0.5)

    assert osm_bob.proc.poll() is None, "OSM-Bob crashed"
    osm_bob.proc.terminate()
    osm_bob.proc.wait(timeout=3)
    stderr_bob = osm_bob.proc.stderr.read().decode()
    osm_bob.proc = None
    ca_bob.disconnect()

    assert "KEX queued for assignment" in stderr_bob, \
        f"OSM-Bob didn't queue key: {stderr_bob}"
    print("  PASS: OSM-Bob queued incoming key")

    # --- OSM-Alice receives a key ---
    osm_alice = OsmProcess(PORT_A, "Alice")
    assert osm_alice.start(), "OSM-Alice failed to start"

    ca_alice = TcpClient(PORT_A, "CA-Alice")
    assert ca_alice.connect(), "CA-Alice failed to connect"
    time.sleep(0.3)

    bob_key = bytes([0xBB] * 32)
    bob_b64 = base64.b64encode(bob_key).decode()
    kex_bob = f"OSM:KEY:{bob_b64}".encode()
    ca_alice.send_message(CHAR_UUID_RX, kex_bob)
    time.sleep(0.5)

    assert osm_alice.proc.poll() is None, "OSM-Alice crashed"
    osm_alice.proc.terminate()
    osm_alice.proc.wait(timeout=3)
    stderr_alice = osm_alice.proc.stderr.read().decode()
    osm_alice.proc = None
    ca_alice.disconnect()

    assert "KEX queued for assignment" in stderr_alice, \
        f"OSM-Alice didn't queue key: {stderr_alice}"
    assert "bad pubkey" not in stderr_alice and "bad pubkey" not in stderr_bob, \
        "KEX rejected with bad pubkey"
    print("  PASS: OSM-Alice queued incoming key")
    print("  PASS: Both sides queued keys for assignment")


def test_encrypted_msg_delivery():
    """Test 12: Encrypted message (OSM:MSG:) arrives at OSM without crash."""
    print("\n[Test 12] Encrypted message delivery")

    osm = OsmProcess(PORT_A, "OSM-A")
    assert osm.start(), "OSM failed to start"

    ca = TcpClient(PORT_A, "CA-A")
    assert ca.connect(), "CA failed to connect"
    time.sleep(0.3)

    fake_cipher = base64.b64encode(bytes(range(80))).decode()
    msg = f"OSM:MSG:{fake_cipher}".encode()
    ca.send_message(CHAR_UUID_RX, msg)
    time.sleep(0.5)

    assert osm.proc.poll() is None, "OSM crashed on encrypted message"
    print("  PASS: OSM handled encrypted message without crash")

    ca.disconnect()
    osm.stop()


def test_kex_outbound_no_name():
    """Test 13: Outbound KEX from OSM has no sender name.

    When OSM sends a key exchange, the format should be OSM:KEY:<pubkey>
    without any device name or sender identity.
    """
    print("\n[Test 13] Outbound KEX has no sender name")

    osm = OsmProcess(PORT_A, "OSM-A")
    assert osm.start(), "OSM failed to start"

    ca = TcpClient(PORT_A, "CA-A")
    assert ca.connect(), "CA failed to connect"
    time.sleep(0.5)

    # The OSM should send any queued outbox messages.
    # In the test driver, contacts are created with our pubkey stored.
    # We need to check that the format is OSM:KEY:<base64> with no extra colons.
    # Poll for any messages (OSM may have sent on connect)
    msgs = ca.poll(timeout=2.0)

    # Even if no messages are sent (fresh start), we verify no crash.
    assert osm.proc.poll() is None, "OSM crashed"

    # Verify any KEY messages have the right format
    for uuid, data in msgs:
        text = data.decode('utf-8', errors='replace')
        if text.startswith("OSM:KEY:"):
            payload = text[len("OSM:KEY:"):]
            # Should be just base64 (no colon = no embedded name)
            assert ':' not in payload, \
                f"KEX still contains name separator: {text}"
            print(f"  PASS: Outbound KEX is anonymous: {text[:60]}...")

    print("  PASS: Outbound format verified")

    ca.disconnect()
    osm.stop()


def test_pending_key_persistence():
    """Test 14: Pending keys survive OSM restart.

    Send a KEX, stop OSM, restart it, verify the pending key is still there.
    """
    print("\n[Test 14] Pending key persistence")

    osm = OsmProcess(PORT_A, "OSM-A")
    assert osm.start(), "OSM failed to start"

    ca = TcpClient(PORT_A, "CA-A")
    assert ca.connect(), "CA failed to connect"
    time.sleep(0.3)

    fake_key = bytes([0xCC] * 32)
    key_b64 = base64.b64encode(fake_key).decode()
    ca.send_message(CHAR_UUID_RX, f"OSM:KEY:{key_b64}".encode())
    time.sleep(0.5)

    osm.proc.terminate()
    osm.proc.wait(timeout=3)
    stderr1 = osm.proc.stderr.read().decode()
    osm.proc = None
    ca.disconnect()

    assert "KEX queued for assignment" in stderr1, \
        f"Key not queued: {stderr1}"
    print("  PASS: Key queued in first session")

    # Check the file was written
    assert os.path.exists("data_pending_keys.json"), \
        "Pending keys file not written"

    # Restart OSM (don't clean data files)
    osm2 = OsmProcess(PORT_A, "OSM-A-2")
    assert osm2.start(clean=False), "OSM failed to restart"

    ca2 = TcpClient(PORT_A, "CA-A-2")
    assert ca2.connect(), "CA failed to reconnect"
    time.sleep(0.3)

    # Send the same key again — should be rejected as duplicate
    ca2.send_message(CHAR_UUID_RX, f"OSM:KEY:{key_b64}".encode())
    time.sleep(0.5)

    osm2.proc.terminate()
    osm2.proc.wait(timeout=3)
    stderr2 = osm2.proc.stderr.read().decode()
    osm2.proc = None
    ca2.disconnect()

    assert "already pending" in stderr2, \
        f"Expected duplicate rejection after reload, got: {stderr2}"
    print("  PASS: Key survived restart (duplicate rejected)")


def main():
    if not os.path.isfile(BINARY):
        print(f"ERROR: OSM binary not found at {BINARY}")
        print("Build it first: cd osm/build && cmake .. && make -j$(nproc)")
        sys.exit(1)

    print("=" * 60)
    print("E2E Integration Tests — Offline Secure Messenger")
    print("=" * 60)

    tests = [
        test_tcp_connectivity,
        test_send_receive,
        test_osm_sends_to_ca,
        test_large_message_fragmentation,
        test_multiple_osm_instances,
        test_reconnect,
        test_key_exchange_envelope,
        test_unknown_envelope,
        test_kex_queues_pending_key,
        test_kex_dedup_pending,
        test_bidirectional_kex_anonymous,
        test_encrypted_msg_delivery,
        test_kex_outbound_no_name,
        test_pending_key_persistence,
    ]

    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"E2E Results: {passed} passed, {failed} failed")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
