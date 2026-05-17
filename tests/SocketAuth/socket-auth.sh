#!/bin/bash
# End-to-end test for ENABLE_SOCKET_AUTH:
#   - boots trojan2 manager with a fresh SQLite DB
#   - registers a user via the manager's REST API
#   - boots a trojan-server pointed at the manager UNIX socket (no MySQL)
#   - boots a trojan-client that connects with the just-registered password
#   - SOCKS5s a curl request through the tunnel and checks the body matches
#
# Args:
#   $1 -> path to the trojan binary (built with -DENABLE_SOCKET_AUTH=ON)
#   $2 -> path to the trojan-manager binary
set -eu

if [[ "$#" -ne 2 ]]; then
    echo "usage: $0 path_to_trojan path_to_trojan-manager" >&2
    exit 1
fi

TROJAN="$1"
MANAGER="$2"

for cmd in curl nc openssl python3 jq; do
    command -v "$cmd" >/dev/null || { echo "$cmd is required" >&2; exit 1; }
done

TMPDIR="$(mktemp -d)"
echo "$TMPDIR"
cd "$TMPDIR"

exec 2>> test.log

# --- TLS cert ---
yes '' | openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj '/CN=localhost'

# --- backend HTTP server (the thing trojan ultimately forwards to) ---
mkdir -p backend
echo socket-auth-ok > backend/whoami.txt
( cd backend && python3 -m http.server 20080 > backend.log 2>&1 ) &
BACKEND_PID="$!"

wait_port() { until nc -z 127.0.0.1 "$1"; do sleep 0.1; done; }

# --- trojan2 manager ---
cat > manager.json <<EOF
{
  "http_addr": "127.0.0.1:28080",
  "socket_path": "$TMPDIR/manager.sock",
  "database_path": "$TMPDIR/manager.db",
  "jwt_secret": "socket-auth-smoke-test"
}
EOF
printf 'smoke-admin-pass\nsmoke-admin-pass\n' | "$MANAGER" -config manager.json admin add smoke-admin >/dev/null

"$MANAGER" -config manager.json > manager.log 2>&1 &
MANAGER_PID="$!"
wait_port 28080

# --- register user ---
PASSWORD="socket-auth-test-password"
TOKEN=$(curl -s -X POST http://127.0.0.1:28080/api/v1/auth/login \
        -H 'content-type: application/json' \
        -d '{"username":"smoke-admin","password":"smoke-admin-pass"}' | jq -r .token)
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     http://127.0.0.1:28080/api/v1/users \
     -d "{\"username\":\"alice\",\"password\":\"$PASSWORD\",\"quota_bytes\":0}" > /dev/null

# --- trojan server (socket auth, no MySQL, no static password) ---
cat > server.json <<EOF
{
  "run_type": "server",
  "local_addr": "127.0.0.1",
  "local_port": 20443,
  "remote_addr": "127.0.0.1",
  "remote_port": 20080,
  "password": [],
  "log_level": 0,
  "ssl": {"cert":"cert.pem","key":"key.pem"},
  "tcp": {"no_delay":true,"keep_alive":true},
  "mysql": {"enabled":false,"server_addr":"","server_port":0,"database":"","username":"","password":"","key":"","cert":"","ca":""},
  "manager_socket": {"enabled":true,"socket_path":"$TMPDIR/manager.sock"}
}
EOF

# --- trojan client (knows the registered password) ---
cat > client.json <<EOF
{
  "run_type": "client",
  "local_addr": "127.0.0.1",
  "local_port": 21080,
  "remote_addr": "127.0.0.1",
  "remote_port": 20443,
  "password": ["$PASSWORD"],
  "log_level": 0,
  "ssl": {"verify":true,"verify_hostname":false,"cert":"cert.pem","sni":"localhost"},
  "tcp": {"no_delay":true,"keep_alive":true}
}
EOF

"$TROJAN" -t server.json
"$TROJAN" server.json -l server.log &
SERVER_PID="$!"
"$TROJAN" -t client.json
"$TROJAN" client.json -l client.log &
CLIENT_PID="$!"

wait_port 20443
wait_port 21080
# give the SocketAuthenticator a moment to receive the snapshot
sleep 1

# --- the actual end-to-end probe ---
RESPONSE=$(curl -s --socks5 127.0.0.1:21080 http://127.0.0.1:20080/whoami.txt)

kill -KILL "$BACKEND_PID" "$MANAGER_PID" "$SERVER_PID" "$CLIENT_PID" 2>/dev/null || true

if [[ "$RESPONSE" == "socket-auth-ok" ]]; then
    echo "PASS"
    exit 0
fi
echo "FAIL: got '$RESPONSE'"
echo "--- server.log ---"; cat server.log
echo "--- client.log ---"; cat client.log
echo "--- manager.log ---"; cat manager.log
exit 1
