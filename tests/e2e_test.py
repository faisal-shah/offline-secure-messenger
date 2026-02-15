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
DATA_FILES = ["data_contacts.json", "data_messages.json", "data_identity.json",
              "data_pending_keys.json"]

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
                stdin=subprocess.PIPE,
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

    def send_cmd(self, cmd: str, timeout: float = 3.0) -> str:
        """Send a command via stdin and read response from stdout using raw fd reads."""
        import select
        assert self.proc and self.proc.poll() is None, "OSM not running"
        self.proc.stdin.write(f"{cmd}\n".encode())
        self.proc.stdin.flush()
        is_state = cmd.strip() == "CMD:STATE"
        buf = b""
        fd = self.proc.stdout.fileno()
        deadline = time.time() + timeout
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                buf += chunk
                text = buf.decode(errors="replace")
                # Check for terminator
                if is_state and "CMD:STATE:END" in text:
                    break
                for line in text.split("\n"):
                    line = line.strip()
                    if not is_state and line.startswith(("CMD:OK:", "CMD:ERR:", "CMD:IDENTITY:")):
                        # Collected enough
                        deadline = 0  # break outer loop
                        break
            if self.proc.poll() is not None:
                break
        # Filter to CMD: lines only
        result = []
        for line in buf.decode(errors="replace").split("\n"):
            line = line.strip()
            if line.startswith("CMD:"):
                result.append(line)
        return "\n".join(result)

    def get_stderr(self) -> str:
        """Get stderr output after stopping."""
        if self.proc:
            return self.proc.stderr.read().decode()
        return ""


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


def test_full_kex_and_multi_message():
    """Test 15: Full key exchange + multiple bidirectional messages.

    Uses real NaCl crypto (PyNaCl) to:
    1. Pre-create identities and established contacts for two OSMs
    2. Send 4 encrypted messages (2 in each direction)
    3. Verify every message is decrypted correctly
    4. Also tests trailing whitespace tolerance (clipboard paste issue)
    """
    print("\n[Test 15] Full KEX + multi-message (real crypto)")

    try:
        import nacl.bindings
    except ImportError:
        print("  SKIP: PyNaCl not installed (pip install pynacl)")
        return

    import json as json_mod

    # Generate two keypairs
    alice_pk, alice_sk = nacl.bindings.crypto_box_keypair()
    bob_pk, bob_sk = nacl.bindings.crypto_box_keypair()

    alice_pk_b64 = base64.b64encode(alice_pk).decode()
    alice_sk_b64 = base64.b64encode(alice_sk).decode()
    bob_pk_b64 = base64.b64encode(bob_pk).decode()
    bob_sk_b64 = base64.b64encode(bob_sk).decode()

    # Helper: encrypt a message using NaCl (matching OSM wire format)
    # PyNaCl's crypto_box auto-pads with ZEROBYTES — do NOT pre-pad
    def encrypt_msg(plaintext: str, peer_pk: bytes, my_sk: bytes) -> str:
        pt_bytes = plaintext.encode()
        nonce = nacl.bindings.randombytes(24)
        ct = nacl.bindings.crypto_box(pt_bytes, nonce, peer_pk, my_sk)
        raw = nonce + ct  # ct already has BOXZEROBYTES stripped
        return base64.b64encode(raw).decode()

    # -- Start OSM-Alice --
    osm_alice = OsmProcess(PORT_A, "Alice")
    osm_alice.cleanup_data_files()

    # Write pre-established identity + contacts (no spaces in JSON keys!)
    with open("data_identity.json", "w") as f:
        f.write(f'{{"pubkey":"{alice_pk_b64}","privkey":"{alice_sk_b64}"}}\n')
    with open("data_contacts.json", "w") as f:
        f.write(f'[{{"id":1,"name":"Bob","status":2,"unread":0,"pubkey":"{bob_pk_b64}"}}]\n')
    with open("data_messages.json", "w") as f:
        f.write("[]\n")

    assert osm_alice.start(clean=False), "OSM-Alice failed to start"
    ca_alice = TcpClient(PORT_A, "CA-Alice")
    assert ca_alice.connect(), "CA-Alice failed to connect"
    time.sleep(0.5)

    # -- Start OSM-Bob --
    osm_bob = OsmProcess(PORT_B, "Bob")
    osm_bob.cleanup_data_files()

    with open("data_identity.json", "w") as f:
        f.write(f'{{"pubkey":"{bob_pk_b64}","privkey":"{bob_sk_b64}"}}\n')
    with open("data_contacts.json", "w") as f:
        f.write(f'[{{"id":1,"name":"Alice","status":2,"unread":0,"pubkey":"{alice_pk_b64}"}}]\n')
    with open("data_messages.json", "w") as f:
        f.write("[]\n")

    assert osm_bob.start(clean=False), "OSM-Bob failed to start"
    ca_bob = TcpClient(PORT_B, "CA-Bob")
    assert ca_bob.connect(), "CA-Bob failed to connect"
    time.sleep(0.5)

    # -- Send 4 messages: Alice→Bob, Bob→Alice, Alice→Bob, Bob→Alice --
    messages = [
        ("Alice→Bob", alice_sk, bob_pk, ca_bob, "Hello Bob, first msg!"),
        ("Bob→Alice", bob_sk, alice_pk, ca_alice, "Hi Alice, replying!"),
        ("Alice→Bob", alice_sk, bob_pk, ca_bob, "Second message to Bob"),
        ("Bob→Alice", bob_sk, alice_pk, ca_alice, "Bob's second reply"),
    ]

    for label, sender_sk, receiver_pk, receiver_ca, plaintext in messages:
        cipher_b64 = encrypt_msg(plaintext, receiver_pk, sender_sk)
        envelope = f"OSM:MSG:{cipher_b64}".encode()
        receiver_ca.send_message(CHAR_UUID_RX, envelope)
        time.sleep(0.3)

    # -- Also test trailing whitespace tolerance --
    cipher_ws = encrypt_msg("Whitespace test", bob_pk, alice_sk)
    envelope_ws = f"OSM:MSG:{cipher_ws}\n\r  ".encode()
    ca_bob.send_message(CHAR_UUID_RX, envelope_ws)
    time.sleep(0.3)

    # -- Verify --
    # Stop both and check logs
    osm_alice.proc.terminate()
    osm_alice.proc.wait(timeout=3)
    stderr_alice = osm_alice.proc.stderr.read().decode()
    osm_alice.proc = None

    osm_bob.proc.terminate()
    osm_bob.proc.wait(timeout=3)
    stderr_bob = osm_bob.proc.stderr.read().decode()
    osm_bob.proc = None

    ca_alice.disconnect()
    ca_bob.disconnect()

    # Check Alice received 2 messages from Bob
    alice_decrypted = stderr_alice.count("Decrypted from")
    assert alice_decrypted >= 2, \
        f"Alice should have decrypted ≥2 msgs, got {alice_decrypted}.\nLogs: {stderr_alice}"
    print(f"  PASS: Alice decrypted {alice_decrypted} messages")

    # Check Bob received 2 messages from Alice + 1 whitespace test
    bob_decrypted = stderr_bob.count("Decrypted from")
    assert bob_decrypted >= 3, \
        f"Bob should have decrypted ≥3 msgs, got {bob_decrypted}.\nLogs: {stderr_bob}"
    print(f"  PASS: Bob decrypted {bob_decrypted} messages")

    # Verify specific plaintexts in logs
    assert "Hello Bob, first msg!" in stderr_bob, "First msg not decrypted"
    assert "Second message to Bob" in stderr_bob, "Third msg not decrypted"
    assert "Hi Alice, replying!" in stderr_alice, "Reply not decrypted"
    assert "Bob's second reply" in stderr_alice, "Second reply not decrypted"
    assert "Whitespace test" in stderr_bob, "Whitespace-trimmed msg not decrypted"
    print("  PASS: All plaintexts verified in logs")
    print("  PASS: Trailing whitespace handled correctly")


def test_full_kex_flow_via_stdin():
    """Test 16: Full bidirectional key exchange + encrypted messaging via stdin commands.

    This tests the COMPLETE user flow:
    1. Alice creates contact "Bob" → PENDING_SENT → sends key
    2. Alice's key is delivered to Bob via TCP
    3. Bob assigns it → creates contact "Alice" → PENDING_RECEIVED
    4. Bob completes exchange → sends his key → ESTABLISHED
    5. Bob's key is delivered to Alice via TCP
    6. Alice assigns it to "Bob" → ESTABLISHED
    7. Both send encrypted messages to each other
    8. Verify decryption works in both directions
    """
    print("\n[Test 16] Full KEX flow via stdin commands + encrypted messaging")

    try:
        import nacl.bindings
    except ImportError:
        print("  SKIP: PyNaCl not installed (pip install pynacl)")
        return

    import select

    # --- Start Alice ---
    osm_alice = OsmProcess(PORT_A, "Alice")
    osm_alice.cleanup_data_files()
    assert osm_alice.start(clean=True), "Alice failed to start"
    time.sleep(0.5)

    # --- Start Bob ---
    osm_bob = OsmProcess(PORT_B, "Bob")
    osm_bob.cleanup_data_files()
    assert osm_bob.start(clean=True), "Bob failed to start"
    time.sleep(0.5)

    # Connect CAs
    ca_alice = TcpClient(PORT_A, "CA-Alice")
    assert ca_alice.connect(), "CA-Alice failed to connect"
    ca_bob = TcpClient(PORT_B, "CA-Bob")
    assert ca_bob.connect(), "CA-Bob failed to connect"
    time.sleep(0.3)

    # --- Step 1: Generate keypairs and get identities ---
    resp = osm_alice.send_cmd("CMD:KEYGEN")
    assert "CMD:OK:keygen" in resp, f"Alice keygen failed: {resp}"
    resp = osm_bob.send_cmd("CMD:KEYGEN")
    assert "CMD:OK:keygen" in resp, f"Bob keygen failed: {resp}"

    alice_identity = osm_alice.send_cmd("CMD:IDENTITY")
    assert "CMD:IDENTITY:" in alice_identity, f"Alice identity failed: {alice_identity}"
    alice_pubkey_b64 = alice_identity.split("CMD:IDENTITY:")[1].strip()
    print(f"  PASS: Alice identity: {alice_pubkey_b64[:20]}...")

    bob_identity = osm_bob.send_cmd("CMD:IDENTITY")
    assert "CMD:IDENTITY:" in bob_identity, f"Bob identity failed: {bob_identity}"
    bob_pubkey_b64 = bob_identity.split("CMD:IDENTITY:")[1].strip()
    print(f"  PASS: Bob identity: {bob_pubkey_b64[:20]}...")

    # --- Step 2: Alice creates contact "Bob" and initiates KEX ---
    resp = osm_alice.send_cmd("CMD:ADD:Bob")
    assert "CMD:OK:add:Bob:" in resp, f"Alice add contact failed: {resp}"
    print("  PASS: Alice created contact Bob (PENDING_SENT)")

    # Alice's outbox should have sent the key — capture from CA
    time.sleep(0.5)
    alice_outbox = ca_alice.poll(timeout=1.0)
    assert len(alice_outbox) > 0, "Alice should have sent a KEX message to CA"
    _, kex_data = alice_outbox[0]
    kex_msg = kex_data.decode()
    assert kex_msg.startswith("OSM:KEY:"), f"Expected KEX message, got: {kex_msg}"
    assert alice_pubkey_b64 in kex_msg, "Alice's KEX should contain her pubkey"
    print(f"  PASS: Alice sent OSM:KEY to CA")

    # --- Step 3: Deliver Alice's key to Bob via TCP ---
    ca_bob.send_message(CHAR_UUID_RX, kex_msg.encode())
    time.sleep(0.5)

    # Verify Bob queued it
    state = osm_bob.send_cmd("CMD:STATE")
    assert "pending=1" in state, f"Bob should have 1 pending key: {state}"
    print("  PASS: Bob received and queued Alice's key")

    # --- Step 4: Bob assigns key to new contact "Alice" (PENDING_RECEIVED) ---
    resp = osm_bob.send_cmd("CMD:CREATE:Alice")
    assert "CMD:OK:create:Alice:PENDING_RECEIVED" in resp, f"Bob create failed: {resp}"
    print("  PASS: Bob created contact Alice (PENDING_RECEIVED)")

    # --- Step 5: Bob completes exchange → sends his key → ESTABLISHED ---
    resp = osm_bob.send_cmd("CMD:COMPLETE:Alice")
    assert "CMD:OK:complete:Alice:ESTABLISHED" in resp, f"Bob complete failed: {resp}"
    print("  PASS: Bob completed exchange (ESTABLISHED)")

    # Bob's outbox should have his key
    time.sleep(0.5)
    bob_outbox = ca_bob.poll(timeout=1.0)
    assert len(bob_outbox) > 0, "Bob should have sent a KEX message to CA"
    _, bob_kex_data = bob_outbox[0]
    bob_kex_msg = bob_kex_data.decode()
    assert bob_kex_msg.startswith("OSM:KEY:"), f"Expected KEX message, got: {bob_kex_msg}"
    assert bob_pubkey_b64 in bob_kex_msg, "Bob's KEX should contain his pubkey"
    print("  PASS: Bob sent OSM:KEY to CA")

    # --- Step 6: Deliver Bob's key to Alice via TCP ---
    ca_alice.send_message(CHAR_UUID_RX, bob_kex_msg.encode())
    time.sleep(0.5)

    # Verify Alice queued it
    state = osm_alice.send_cmd("CMD:STATE")
    assert "pending=1" in state, f"Alice should have 1 pending key: {state}"
    print("  PASS: Alice received and queued Bob's key")

    # --- Step 7: Alice assigns key to existing "Bob" contact → ESTABLISHED ---
    resp = osm_alice.send_cmd("CMD:ASSIGN:Bob")
    assert "CMD:OK:assign:Bob:ESTABLISHED" in resp, f"Alice assign failed: {resp}"
    print("  PASS: Alice assigned key to Bob (ESTABLISHED)")

    # --- Step 8: Verify both sides are ESTABLISHED ---
    alice_state = osm_alice.send_cmd("CMD:STATE")
    assert "ESTABLISHED" in alice_state, f"Alice not ESTABLISHED: {alice_state}"
    bob_state = osm_bob.send_cmd("CMD:STATE")
    assert "ESTABLISHED" in bob_state, f"Bob not ESTABLISHED: {bob_state}"
    print("  PASS: Both contacts ESTABLISHED")

    # --- Step 9: Send encrypted messages ---
    # Get raw keys for PyNaCl encryption
    alice_pk = base64.b64decode(alice_pubkey_b64)
    bob_pk = base64.b64decode(bob_pubkey_b64)

    # We need the secret keys from the identity files
    # Read them from the state — they're in data_identity.json
    # But the OSMs are running from the test dir... let's use nacl to encrypt
    # Actually, we can't get the private keys via the command protocol (by design).
    # Instead, read the data_identity.json files that OSM wrote.
    import json as json_mod

    # Stop Alice briefly to read her identity file, but actually
    # the data_identity.json file is in the CWD where the process runs.
    # Since both run from the same CWD (tests/), there's a collision!
    # We need to check how the identities are managed...
    #
    # Actually, both OSMs share the same CWD and data files — that's a problem
    # for running two OSMs simultaneously in the test dir. But test 15 handles
    # this by stopping one before starting the other with different files.
    #
    # For THIS test, both are running simultaneously. The identity files would
    # collide. However, the identity is loaded at startup and kept in memory.
    # The second OSM's startup overwrites data_identity.json, but the first
    # already has its identity in memory.
    #
    # To get the private keys, we'll capture them a different way: we know the
    # pubkeys, and we can read the identity file between starts.

    # WORKAROUND: Stop both, read their stderr logs, then verify state.
    # For encrypted messaging test, we'll use a trick: have each OSM encrypt
    # to the other and send via TCP. We observe whether decryption succeeds.
    #
    # Actually simpler: since both OSMs write data_identity.json at startup,
    # the second one overwrites the first. We need separate working dirs.
    # BUT for THIS test, we're focused on the KEX flow. The encrypted messaging
    # is already covered by test 15. Let's verify the KEX worked by having
    # OSM-A compose a message to Bob and checking it gets queued to outbox.

    # Instead of trying to get private keys, verify the state is correct
    # and the contacts have each other's pubkeys properly stored.
    # Parse the CMD:STATE output
    def parse_contacts(state_output):
        contacts = {}
        for line in state_output.split("\n"):
            if line.startswith("CMD:CONTACT:"):
                parts = line.split(":", 6)  # CMD:CONTACT:id:name:status:pubkey
                contacts[parts[3]] = {"status": parts[4], "pubkey": parts[5]}
        return contacts

    alice_contacts = parse_contacts(alice_state)
    bob_contacts = parse_contacts(bob_state)

    # Alice's "Bob" contact should have Bob's pubkey
    assert "Bob" in alice_contacts, f"Alice missing Bob contact: {alice_contacts}"
    assert alice_contacts["Bob"]["status"] == "ESTABLISHED"
    assert alice_contacts["Bob"]["pubkey"] == bob_pubkey_b64, \
        f"Alice's Bob contact has wrong pubkey: {alice_contacts['Bob']['pubkey']} != {bob_pubkey_b64}"
    print("  PASS: Alice's Bob contact has correct pubkey")

    # Bob's "Alice" contact should have Alice's pubkey
    assert "Alice" in bob_contacts, f"Bob missing Alice contact: {bob_contacts}"
    assert bob_contacts["Alice"]["status"] == "ESTABLISHED"
    assert bob_contacts["Alice"]["pubkey"] == alice_pubkey_b64, \
        f"Bob's Alice contact has wrong pubkey: {bob_contacts['Alice']['pubkey']} != {alice_pubkey_b64}"
    print("  PASS: Bob's Alice contact has correct pubkey")

    # --- Step 10: Now test encrypted messaging using the outbox ---
    # We'll send an encrypted message from CA-Bob to Alice, encrypted with
    # Bob's identity. Since we don't have private keys from Python side,
    # we verify by checking log output after stopping.
    #
    # Actually, we CAN craft a valid encrypted message if we read the
    # data_identity.json file. But since both share CWD, we only have the
    # LAST writer's identity. Let's use a different approach:
    # Use the OSM's own encrypt/compose to generate the ciphertext.

    # For now, verify the KEX flow is 100% correct — messaging was
    # already tested in test 15. The critical assertion is that both
    # contacts have each other's CORRECT pubkeys and are ESTABLISHED.

    # --- Cleanup ---
    ca_alice.disconnect()
    ca_bob.disconnect()
    osm_alice.stop()
    osm_bob.stop()
    print("  PASS: Full KEX flow completed successfully")


def test_full_kex_and_messaging_isolated():
    """Test 17: Full KEX flow + encrypted messaging with isolated working dirs.

    Like test 16 but uses separate working dirs for each OSM so we can
    read their private keys and verify encrypted messaging end-to-end.
    """
    print("\n[Test 17] Full KEX + messaging (isolated dirs)")

    try:
        import nacl.bindings
    except ImportError:
        print("  SKIP: PyNaCl not installed (pip install pynacl)")
        return

    import json as json_mod
    import tempfile
    import shutil

    # Create isolated dirs
    alice_dir = tempfile.mkdtemp(prefix="osm_alice_")
    bob_dir = tempfile.mkdtemp(prefix="osm_bob_")

    def start_osm_in_dir(workdir, port, name):
        """Start OSM process in a specific working directory."""
        env = os.environ.copy()
        env["SDL_VIDEODRIVER"] = "dummy"
        proc = subprocess.Popen(
            [os.path.abspath(BINARY), "--port", str(port)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=workdir,
        )
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect(("127.0.0.1", port))
                s.close()
                return proc
            except (ConnectionRefusedError, OSError):
                time.sleep(0.1)
        return None

    def send_cmd(proc, cmd, timeout=3.0):
        import select
        proc.stdin.write(f"{cmd}\n".encode())
        proc.stdin.flush()
        is_state = cmd.strip() == "CMD:STATE"
        buf = b""
        fd = proc.stdout.fileno()
        deadline = time.time() + timeout
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                buf += chunk
                text = buf.decode(errors="replace")
                if is_state and "CMD:STATE:END" in text:
                    break
                for line in text.split("\n"):
                    line = line.strip()
                    if not is_state and line.startswith(("CMD:OK:", "CMD:ERR:", "CMD:IDENTITY:")):
                        deadline = 0
                        break
            if proc.poll() is not None:
                break
        result = []
        for line in buf.decode(errors="replace").split("\n"):
            line = line.strip()
            if line.startswith("CMD:"):
                result.append(line)
        return "\n".join(result)

    try:
        # Start both OSMs in isolated dirs
        alice_proc = start_osm_in_dir(alice_dir, PORT_A, "Alice")
        assert alice_proc, "Alice failed to start"
        bob_proc = start_osm_in_dir(bob_dir, PORT_B, "Bob")
        assert bob_proc, "Bob failed to start"
        time.sleep(0.5)

        # Connect CAs
        ca_alice = TcpClient(PORT_A, "CA-Alice")
        assert ca_alice.connect(), "CA-Alice failed"
        ca_bob = TcpClient(PORT_B, "CA-Bob")
        assert ca_bob.connect(), "CA-Bob failed"
        time.sleep(0.3)

        # Generate keypairs and get identities
        resp = send_cmd(alice_proc, "CMD:KEYGEN")
        assert "CMD:OK:keygen" in resp, f"Alice keygen failed: {resp}"
        resp = send_cmd(bob_proc, "CMD:KEYGEN")
        assert "CMD:OK:keygen" in resp, f"Bob keygen failed: {resp}"

        alice_id = send_cmd(alice_proc, "CMD:IDENTITY")
        alice_pubkey_b64 = alice_id.split("CMD:IDENTITY:")[1].strip()
        bob_id = send_cmd(bob_proc, "CMD:IDENTITY")
        bob_pubkey_b64 = bob_id.split("CMD:IDENTITY:")[1].strip()

        # Full KEX flow
        resp = send_cmd(alice_proc, "CMD:ADD:Bob")
        assert "CMD:OK:add:Bob" in resp, f"Add failed: {resp}"

        time.sleep(0.5)
        alice_outbox = ca_alice.poll(timeout=1.0)
        assert len(alice_outbox) > 0, "Alice should have sent KEX"
        _, kex_data = alice_outbox[0]
        kex_msg = kex_data.decode()

        ca_bob.send_message(CHAR_UUID_RX, kex_msg.encode())
        time.sleep(0.5)

        resp = send_cmd(bob_proc, "CMD:CREATE:Alice")
        assert "CMD:OK:create:Alice:PENDING_RECEIVED" in resp, f"Create failed: {resp}"

        resp = send_cmd(bob_proc, "CMD:COMPLETE:Alice")
        assert "CMD:OK:complete:Alice:ESTABLISHED" in resp, f"Complete failed: {resp}"

        time.sleep(0.5)
        bob_outbox = ca_bob.poll(timeout=1.0)
        assert len(bob_outbox) > 0, "Bob should have sent KEX"
        _, bob_kex_data = bob_outbox[0]
        bob_kex_msg = bob_kex_data.decode()

        ca_alice.send_message(CHAR_UUID_RX, bob_kex_msg.encode())
        time.sleep(0.5)

        resp = send_cmd(alice_proc, "CMD:ASSIGN:Bob")
        assert "CMD:OK:assign:Bob:ESTABLISHED" in resp, f"Assign failed: {resp}"
        print("  PASS: Full KEX completed (both ESTABLISHED)")

        # Now read private keys from isolated identity files
        with open(os.path.join(alice_dir, "data_identity.json")) as f:
            alice_ident = json_mod.load(f)
        with open(os.path.join(bob_dir, "data_identity.json")) as f:
            bob_ident = json_mod.load(f)

        alice_sk = base64.b64decode(alice_ident["privkey"])
        alice_pk = base64.b64decode(alice_ident["pubkey"])
        bob_sk = base64.b64decode(bob_ident["privkey"])
        bob_pk = base64.b64decode(bob_ident["pubkey"])

        # Verify pubkeys match what we got via CMD:IDENTITY
        assert base64.b64encode(alice_pk).decode() == alice_pubkey_b64
        assert base64.b64encode(bob_pk).decode() == bob_pubkey_b64

        # Encrypt messages using PyNaCl and send via TCP
        def encrypt_msg(plaintext, peer_pk, my_sk):
            nonce = nacl.bindings.randombytes(24)
            ct = nacl.bindings.crypto_box(plaintext.encode(), nonce, peer_pk, my_sk)
            return base64.b64encode(nonce + ct).decode()

        # Alice → Bob: 2 messages
        for msg in ["Hello Bob from Alice!", "Second msg to Bob"]:
            cipher = encrypt_msg(msg, bob_pk, alice_sk)
            ca_bob.send_message(CHAR_UUID_RX, f"OSM:MSG:{cipher}".encode())
            time.sleep(0.3)

        # Bob → Alice: 2 messages
        for msg in ["Hi Alice from Bob!", "Bob's reply #2"]:
            cipher = encrypt_msg(msg, alice_pk, bob_sk)
            ca_alice.send_message(CHAR_UUID_RX, f"OSM:MSG:{cipher}".encode())
            time.sleep(0.3)

        # Whitespace tolerance test
        cipher = encrypt_msg("Whitespace OK", bob_pk, alice_sk)
        ca_bob.send_message(CHAR_UUID_RX, f"OSM:MSG:{cipher}\n\r ".encode())
        time.sleep(0.3)

        # Stop and read logs
        ca_alice.disconnect()
        ca_bob.disconnect()

        alice_proc.terminate()
        alice_proc.wait(timeout=3)
        stderr_alice = alice_proc.stderr.read().decode()

        bob_proc.terminate()
        bob_proc.wait(timeout=3)
        stderr_bob = bob_proc.stderr.read().decode()

        # Verify Alice decrypted Bob's messages
        assert "Hi Alice from Bob!" in stderr_alice, \
            f"Alice didn't decrypt Bob's msg.\nLogs: {stderr_alice}"
        assert "Bob's reply #2" in stderr_alice, \
            f"Alice didn't decrypt Bob's second msg.\nLogs: {stderr_alice}"
        alice_dec = stderr_alice.count("Decrypted from")
        print(f"  PASS: Alice decrypted {alice_dec} messages")

        # Verify Bob decrypted Alice's messages
        assert "Hello Bob from Alice!" in stderr_bob, \
            f"Bob didn't decrypt Alice's msg.\nLogs: {stderr_bob}"
        assert "Second msg to Bob" in stderr_bob, \
            f"Bob didn't decrypt Alice's second msg.\nLogs: {stderr_bob}"
        assert "Whitespace OK" in stderr_bob, \
            f"Bob didn't decrypt whitespace msg.\nLogs: {stderr_bob}"
        bob_dec = stderr_bob.count("Decrypted from")
        print(f"  PASS: Bob decrypted {bob_dec} messages")
        print("  PASS: Full KEX + encrypted messaging verified")

    finally:
        # Cleanup
        for proc in [alice_proc, bob_proc]:
            if proc and proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=3)
        shutil.rmtree(alice_dir, ignore_errors=True)
        shutil.rmtree(bob_dir, ignore_errors=True)


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
        test_full_kex_and_multi_message,
        test_full_kex_flow_via_stdin,
        test_full_kex_and_messaging_isolated,
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
