#!/bin/bash
# Launch 2 pairs of OSM + Companion App for manual testing.
#
# Pair 1: OSM-Alice (port 19200) + CA-Alice
# Pair 2: OSM-Bob   (port 19201) + CA-Bob
#
# Usage:  ./launch_test_session.sh
# Stop:   ./launch_test_session.sh stop

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
OSM_BIN="$REPO_DIR/osm/build/secure_communicator"
CA_DIR="$REPO_DIR/companion-app"
PIDFILE="/tmp/osm-test-session.pids"
LOGDIR="/tmp/osm-test-logs"

# Ports for the two OSM instances
PORT_ALICE=19200
PORT_BOB=19201

stop_all() {
    if [ -f "$PIDFILE" ]; then
        echo "Stopping test session..."
        while read -r pid name; do
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null && echo "  Stopped $name (PID $pid)" || true
            fi
        done < "$PIDFILE"
        rm -f "$PIDFILE"
        echo "All processes stopped."
    else
        echo "No active test session found."
    fi
}

# Ensure Java trusts TLS inspection proxy certs (corporate networks)
ensure_java_truststore() {
    if [ -f /tmp/cacerts-patched ]; then
        return 0
    fi
    echo "  Patching Java truststore for TLS proxy..."
    cp /etc/ssl/certs/java/cacerts /tmp/cacerts-patched 2>/dev/null || return 1
    # Extract proxy CA chain from any HTTPS host
    echo | openssl s_client -connect services.gradle.org:443 \
        -servername services.gradle.org -showcerts 2>/dev/null \
        | awk '/BEGIN CERT/,/END CERT/' > /tmp/proxy-chain.pem
    csplit -z -f /tmp/proxy-cert- /tmp/proxy-chain.pem \
        '/-----BEGIN CERTIFICATE-----/' '{*}' >/dev/null 2>&1
    for cert in /tmp/proxy-cert-*; do
        alias="proxy-$(basename "$cert")"
        keytool -importcert -noprompt -keystore /tmp/cacerts-patched \
            -storepass changeit -alias "$alias" -file "$cert" >/dev/null 2>&1
    done
    rm -f /tmp/proxy-chain.pem /tmp/proxy-cert-*
    echo "  Truststore patched: /tmp/cacerts-patched"
}

if [ "${1:-}" = "stop" ]; then
    stop_all
    exit 0
fi

# Stop any previous session
stop_all 2>/dev/null

# Check prerequisites
if [ ! -f "$OSM_BIN" ]; then
    echo "ERROR: OSM binary not found. Build it first:"
    echo "  cd osm/build && cmake .. && make -j\$(nproc)"
    exit 1
fi

# Clean up stale data so each session starts fresh
rm -f "$REPO_DIR/osm/build/alice/osm_data.img" \
      "$REPO_DIR/osm/build/bob/osm_data.img"

# Create log directory
mkdir -p "$LOGDIR"

echo "============================================================"
echo "  Offline Secure Messenger — Test Session"
echo "============================================================"
echo ""
echo "  OSM-Alice : port $PORT_ALICE"
echo "  OSM-Bob   : port $PORT_BOB"
echo ""
> "$PIDFILE"

# Launch OSM-Alice
cd "$REPO_DIR/osm/build"
mkdir -p alice bob
cd alice
"$OSM_BIN" --port $PORT_ALICE --name Alice 2>"$LOGDIR/osm_alice.log" &
PID=$!
echo "$PID OSM-Alice" >> "$PIDFILE"
echo "  Started OSM-Alice (PID $PID)"

# Launch OSM-Bob
cd "$REPO_DIR/osm/build/bob"
"$OSM_BIN" --port $PORT_BOB --name Bob 2>"$LOGDIR/osm_bob.log" &
PID=$!
echo "$PID OSM-Bob" >> "$PIDFILE"
echo "  Started OSM-Bob   (PID $PID)"

# Wait for both to be listening
sleep 1
for port in $PORT_ALICE $PORT_BOB; do
    if nc -z 127.0.0.1 $port 2>/dev/null; then
        echo "  ✓ Port $port listening"
    else
        echo "  ✗ Port $port NOT listening — check logs"
    fi
done

# Launch CA instances
echo ""
echo "  Starting Companion Apps..."
ensure_java_truststore
export JAVA_TOOL_OPTIONS="-Djavax.net.ssl.trustStore=/tmp/cacerts-patched"

# Check if Gradle is available (wrapper has SSL issues, use local install)
GRADLE=""
if [ -x "/tmp/gradle-8.10/bin/gradle" ]; then
    GRADLE="/tmp/gradle-8.10/bin/gradle"
elif [ -x "$CA_DIR/gradlew" ]; then
    GRADLE="$CA_DIR/gradlew"
fi

if [ -z "$GRADLE" ]; then
    echo "  WARNING: Gradle not found. Downloading..."
    curl -ksL https://services.gradle.org/distributions/gradle-8.10-bin.zip \
        -o /tmp/gradle-8.10.zip 2>/dev/null
    if [ -f /tmp/gradle-8.10.zip ]; then
        unzip -qo /tmp/gradle-8.10.zip -d /tmp/
        GRADLE="/tmp/gradle-8.10/bin/gradle"
    fi
fi

if [ -n "$GRADLE" ] && [ -x "$GRADLE" ]; then
    cd "$CA_DIR"
    # Build once, then launch two instances
    "$GRADLE" :desktopApp:createDistributable --no-daemon > /tmp/ca_build.log 2>&1
    if [ $? -eq 0 ]; then
        DIST_BIN="$CA_DIR/desktopApp/build/compose/binaries/main/app/companion-app/bin/companion-app"
        if [ -x "$DIST_BIN" ]; then
            "$DIST_BIN" --port $PORT_ALICE --title Alice > "$LOGDIR/ca_alice.log" 2>&1 &
            PID=$!
            echo "$PID CA-Alice" >> "$PIDFILE"
            echo "  Started CA-Alice (PID $PID) — port $PORT_ALICE"

            "$DIST_BIN" --port $PORT_BOB --title Bob > "$LOGDIR/ca_bob.log" 2>&1 &
            PID=$!
            echo "$PID CA-Bob" >> "$PIDFILE"
            echo "  Started CA-Bob   (PID $PID) — port $PORT_BOB"
        else
            echo "  WARNING: installDist succeeded but binary not found at $DIST_BIN"
        fi
    else
        echo "  WARNING: Gradle build failed. Check /tmp/ca_build.log"
    fi
else
    echo "  WARNING: Could not find or download Gradle. Skipping CA launch."
    echo "  Run manually: cd companion-app && /tmp/gradle-8.10/bin/gradle :desktopApp:run"
fi

echo ""
echo "============================================================"
echo "  Test Session Running"
echo "============================================================"
echo ""
echo "  Two OSM windows should appear (Alice and Bob)."
echo "  Two Companion App windows (CA-Alice and CA-Bob)."
echo ""
echo "  Workflow to test:"
echo "    1. In OSM-Alice: generate keypair (first launch wizard)"
echo "    2. In OSM-Bob:   generate keypair"
echo "    3. In OSM-Alice: Contacts → Add 'Bob'"
echo "       This sends Alice's pubkey as OSM:KEY:<key> to CA-Alice"
echo "    4. Copy the text from CA-Alice, paste into CA-Bob, send to OSM-Bob"
echo "    5. OSM-Bob receives key → 'Assign Key' screen"
echo "       Create new contact 'Alice' → key exchange continues"
echo "    6. In OSM-Bob: go to Contacts → Alice → Complete Exchange"
echo "       This sends Bob's pubkey to CA-Bob"
echo "    7. Copy from CA-Bob, paste into CA-Alice, send to OSM-Alice"
echo "    8. OSM-Alice: 'Assign Key' → select 'Bob (Pending)' → ESTABLISHED"
echo "    9. Send encrypted messages between Alice and Bob via the CAs"
echo ""
echo "  Logs:"
echo "    OSM-Alice: osm/build/alice/osm_alice.log"
echo "    OSM-Bob:   osm/build/bob/osm_bob.log"
echo "    CA-Alice:  /tmp/ca_alice.log"
echo "    CA-Bob:    /tmp/ca_bob.log"
echo ""
echo "  Stop all: $0 stop"
echo ""
echo "  PIDs saved to: $PIDFILE"
