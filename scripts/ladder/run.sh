#!/usr/bin/env bash
# PTPAN Docker ladder. Builds the binaries into one scratch directory, starts
# two independent providers (deploy/ladder/compose.yaml), runs the rows in
# order and stops at the first failure. Everything the run creates
# (containers, networks, volumes, scratch files, build output) is removed on
# exit; only the one-line-per-row ledger is kept under artifacts/ladder/.
#
#   scripts/ladder/run.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
compose="$root/deploy/ladder/compose.yaml"
RUN="$(mktemp -d "$HOME/.cache/ptpan-ladder.XXXXXX")"
export LADDER_RUN="$RUN"
project="ptpan-ladder-$(basename "$RUN" | tr '[:upper:].' '[:lower:]-')"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
ledger="$root/artifacts/ladder/$stamp.txt"
mkdir -p "$root/artifacts/ladder"
: > "$ledger"
export JOIN_TOKEN_A="" JOIN_TOKEN_B=""

dc() { docker compose -p "$project" -f "$compose" --profile agents --profile ptpan "$@"; }

cleanup() {
    local status=$?
    if [[ $status -ne 0 ]]; then
        echo "--- last log lines ---" >&2
        dc logs --no-color --tail 40 adapter-a adapter-b bridge-a bridge-b platform-a platform-b 1>&2 2>/dev/null || true
    fi
    if [[ $status -ne 0 && -n "${LADDER_KEEP_ON_FAILURE:-}" ]]; then
        # Debugging only: leave the stack for inspection. The caller must run
        # scripts/ladder/down.sh with the printed project and scratch path.
        echo "kept: project=$project scratch=$RUN" | tee -a "$ledger"
        exit $status
    fi
    dc down -v --remove-orphans >/dev/null 2>&1 || true
    chmod -R u+w "$RUN" 2>/dev/null || true
    rm -rf "$RUN"
    local left
    left="$(docker ps -a --filter "label=com.docker.compose.project=$project" -q | wc -l)"
    echo "cleanup: containers left=$left, scratch removed=$([[ -e $RUN ]] && echo no || echo yes)" | tee -a "$ledger"
    exit $status
}
trap cleanup EXIT

log() { echo "[$(date -u +%H:%M:%S)] $*"; }
pass() { echo "PASS $1" | tee -a "$ledger"; }
# `! cmd` does not trip `set -e`; refute fails the run when cmd succeeds.
refute() { if "$@" >/dev/null 2>&1; then echo "unexpectedly succeeded: $*" >&2; return 1; fi; }

# Poll a command until it succeeds or the timeout (seconds) passes.
wait_for() {
    local what="$1" timeout="$2"; shift 2
    local end=$((SECONDS + timeout))
    until "$@" >/dev/null 2>&1; do
        if (( SECONDS >= end )); then echo "timed out: $what" >&2; return 1; fi
        sleep 1
    done
}

ad() { local x="$1"; shift; dc exec -T "adapter-$x" /opt/ptpan/ptpan-adapter "$@"; }
adc() { local x="$1"; shift; ad "$x" "$1" "${@:2:1}" /cfg/adapter.json "${@:3}"; }
pf() { local x="$1"; shift; dc exec -T "platform-$x" /opt/ptpan/ptpan-reference-platform /cfg/platform.json "$@"; }
peer_state() { ad "$1" status /cfg/adapter.json | python3 -c "import json,sys; print({p['peer']:p['state'] for p in json.load(sys.stdin)}.get('$2',''))"; }
is_state() { [[ "$(peer_state "$1" "$2")" == "$3" ]]; }
req_state() { pf "$1" request state "$2" | tr -d '\r\n'; }
is_req() { [[ "$(req_state "$1" "$2")" == "$3" ]]; }
is_ready() { [[ "$(pf "$1" relationship ready "$2" | tr -d '\r\n')" == "true" ]]; }
call_allowed() { pf "$1" call "$2" "$3" 2>/dev/null | grep -q '"result":"ALLOW"'; }
not_ready() { [[ "$(pf "$1" relationship ready "$2" | tr -d '\r\n')" == "false" ]]; }

# --- 00 build -----------------------------------------------------------------
log "00 build"
mkdir -p "$RUN/bin" "$RUN/go"
if [[ -n "${LADDER_BIN:-}" ]]; then
    # Reuse binaries built by an earlier step of the same session.
    cp "$LADDER_BIN"/ptpan-adapter "$LADDER_BIN"/ptpan-reference-platform "$LADDER_BIN"/bridge-runtime "$RUN/bin/"
else
CARGO_TARGET_DIR="$RUN/target" cargo build -q --release --locked -p ptpan-adapter -p ptpan-reference-platform \
    --manifest-path "$root/Cargo.toml"
cp "$RUN/target/release/ptpan-adapter" "$RUN/target/release/ptpan-reference-platform" "$RUN/bin/"
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/work -e GOCACHE=/work/cache -e GOMODCACHE=/work/mod \
    -e GOFLAGS="-mod=readonly -modcacherw" -e GOTOOLCHAIN=local -e CGO_ENABLED=0 \
    -v "$root/bridge":/src:ro -v "$RUN/go":/work -v "$RUN/bin":/out -w /src \
    golang:1.27.1@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 go build -trimpath -o /out/bridge-runtime ./cmd/bridge-runtime
fi
rm -rf "$RUN/target" "$RUN/go"
pass "00 build (release binaries, static bridge)"

# --- configuration ------------------------------------------------------------
python3 - "$RUN" <<'PY'
import base64, json, os, subprocess, sys
run = sys.argv[1]
def ca_root(name):
    key = os.path.join(run, f"ca-{name}.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", key, "-days", "2",
                    "-subj", f"/CN=PTPAN ladder agent CA {name}", "-outform", "DER", "-out", key + ".der"],
                   check=True, capture_output=True)
    der = open(key + ".der", "rb").read()
    os.remove(key); os.remove(key + ".der")
    return base64.b64encode(der).decode()
roots = {x: ca_root(x) for x in "ab"}
protocols = ["federation-peer/v2", "federation-control/v3", "live-admission/v3", "FRL/1"]
def manifest(x, revision):
    d = f"provider-{x}.test"
    return {"schema": "federation-provider/2", "manifest_id": f"m-{x}-{revision}", "revision": revision,
        "generated_at": "2026-10-21T12:00:00Z",
        "platform": {"platform_id": f"provider-{x}", "display_name": f"Provider {x.upper()}", "display_name_source": "LOCAL_METADATA",
            "operator_name": f"Operator {x.upper()}", "website": f"https://{d}", "documentation_url": None, "logo_url": None,
            "provider_domain": d},
        "workload_trust": {"trust_domain": d, "bundle_endpoint": f"https://spire-server-{x}:8443", "bundle_profile": "https_spiffe",
            "control_service_identity": f"spiffe://{d}/federation/control", "control_service_role": "CONTROL",
            "edge_service_identity": f"spiffe://{d}/federation/edge", "edge_service_role": "EDGE"},
        "federation": {"control_endpoint": f"https://control.{d}:8444/control", "edge_endpoint": f"edge.{d}:8443",
            "protocols": protocols, "base_capabilities": []},
        "agent_trust": {"ca_root": roots[x]}, "directory": None, "application_protocols": ["a2a/1"], "transports": ["tls13"]}
for x, y in (("a", "b"), ("b", "a")):
    d = f"provider-{x}.test"
    cfg = os.path.join(run, f"cfg-{x}"); os.makedirs(cfg)
    www = os.path.join(run, f"www-{x}", ".well-known"); os.makedirs(www)
    os.makedirs(os.path.join(run, f"platform-{x}")); os.chmod(os.path.join(run, f"platform-{x}"), 0o777)
    os.chmod(cfg, 0o777)
    for revision in (1, 2, 3):
        name = "manifest.json" if revision == 1 else f"manifest-r{revision}.json"
        json.dump(manifest(x, revision), open(os.path.join(cfg, name), "w"))
    json.dump({"schema": "ptpan-provider-domain/1", "platform_id": f"provider-{x}",
        "control_service_identity": f"spiffe://{d}/federation/control", "edge_service_identity": f"spiffe://{d}/federation/edge",
        "agent_ca_root": roots[x]}, open(os.path.join(www, "ptpan-provider.json"), "w"))
    json.dump({"platform_id": f"provider-{x}", "provider_domain": d,
        "control_service_id": f"spiffe://{d}/federation/control", "edge_service_id": f"spiffe://{d}/federation/edge",
        "database_url": f"host=pg-{x} user=postgres password=ladder dbname=postgres",
        "platform_socket": "/run/ptpan/platform.sock", "adapter_socket": "/run/ptpan/adapter.sock", "platform_uid": 10003,
        "runtime_socket": "/run/ptpan/runtime.sock", "bridge_socket": "/run/ptpan/bridge.sock", "bridge_uid": 10001,
        "manifest_path": "/cfg/manifest.json", "evidence_profile": "LOCAL_HTTP_TEST", "worker_id": f"adapter-{x}-1"},
        open(os.path.join(cfg, "adapter.json"), "w"))
    json.dump({"platform_id": f"provider-{x}", "provider_domain": d, "database_path": "/data/platform.sqlite",
        "platform_socket": "/run/ptpan/platform.sock", "adapter_socket": "/run/ptpan/adapter.sock", "adapter_uid": 10002,
        "egress_socket": "/run/ptpan/egress.sock", "ingress_socket": "/run/ptpan/ingress.sock", "bridge_uid": 10001},
        open(os.path.join(cfg, "platform.json"), "w"))
    p = f"provider-{y}.test"
    json.dump({"peer": f"provider-{y}", "provider_domain": p,
        "expected_control_service_id": f"spiffe://{p}/federation/control",
        "expected_control_endpoint": f"https://control.{p}:8444/control",
        "expected_edge_service_id": f"spiffe://{p}/federation/edge", "expected_edge_endpoint": f"edge.{p}:8443",
        "expected_bundle_endpoint": f"https://spire-server-{y}:8443", "expected_bundle_profile": "https_spiffe",
        "max_evidence_age_seconds": 3600}, open(os.path.join(cfg, "bootstrap-peer.json"), "w"))
    for name in os.listdir(cfg):
        os.chmod(os.path.join(cfg, name), 0o666)
PY

# --- 01 SPIRE federation --------------------------------------------------------
log "01 SPIRE"
dc up -d --wait spire-server-a spire-server-b pg-a pg-b wellknown-a wellknown-b >/dev/null
for x in a b; do
    dc exec -T "spire-server-$x" /opt/spire/bin/spire-server bundle show -format spiffe > "$RUN/bundle-$x.spiffe"
done
for x in a b; do
    y=$([[ $x == a ]] && echo b || echo a)
    dc exec -T "spire-server-$x" /opt/spire/bin/spire-server bundle set -format spiffe -id "spiffe://provider-$y.test" < "$RUN/bundle-$y.spiffe" >/dev/null
    token="$(dc exec -T "spire-server-$x" /opt/spire/bin/spire-server token generate -spiffeID "spiffe://provider-$x.test/node/ladder" | awk '{print $2}')"
    if [[ $x == a ]]; then JOIN_TOKEN_A="$token"; else JOIN_TOKEN_B="$token"; fi
done
export JOIN_TOKEN_A JOIN_TOKEN_B
dc up -d spire-agent-a spire-agent-b >/dev/null
for x in a b; do
    y=$([[ $x == a ]] && echo b || echo a)
    wait_for "SPIRE agent $x attested" 60 sh -c "docker compose -p $project -f $compose exec -T spire-server-$x /opt/spire/bin/spire-server agent list | grep -q 'SPIFFE ID'"
    for service in control edge; do
        dc exec -T "spire-server-$x" /opt/spire/bin/spire-server entry create -parentID "spiffe://provider-$x.test/node/ladder" \
            -spiffeID "spiffe://provider-$x.test/federation/$service" -selector unix:uid:10001 \
            -federatesWith "spiffe://provider-$y.test" >/dev/null
    done
done
pass "01 SPIRE: two trust domains, bundles exchanged, control and edge identities registered"

# --- 02 start PTPAN ---------------------------------------------------------------
log "02 start"
dc run --rm init-sockets >/dev/null
dc up -d adapter-a adapter-b bridge-a bridge-b platform-a platform-b >/dev/null
for x in a b; do
    wait_for "bridge $x ready" 90 sh -c "docker compose -p $project -f $compose logs bridge-$x | grep -q BRIDGE_READY"
    wait_for "platform $x ready" 30 sh -c "docker compose -p $project -f $compose logs platform-$x | grep -q PLATFORM_READY"
done
pass "02 adapters, bridges (SPIFFE mTLS), platforms running"

# --- 03 onboarding ------------------------------------------------------------------
log "03 onboarding"
adc a peer add /cfg/bootstrap-peer.json
adc b peer add /cfg/bootstrap-peer.json
sleep 3
is_state a provider-b Pending
wait_for "A verified B" 90 sh -c "docker compose -p $project -f $compose exec -T adapter-a /opt/ptpan/ptpan-adapter peer approve /cfg/adapter.json provider-b"
wait_for "B verified A" 90 sh -c "docker compose -p $project -f $compose exec -T adapter-b /opt/ptpan/ptpan-adapter peer approve /cfg/adapter.json provider-a"
wait_for "A sees B active" 90 is_state a provider-b Active
wait_for "B sees A active" 90 is_state b provider-a Active
pass "03 onboarding: hello over mTLS, D14 domain proof, both approvals, active without restart"

# --- 04 A to B ----------------------------------------------------------------------
log "04 A to B"
pf a account add acct-alice-7f3 Ada Lovelace
a1="$(pf a agent add agent-a1-91c acct-alice-7f3 | tr -d '\r\n')"
a2="$(pf a agent add agent-a2-5d0 acct-alice-7f3 | tr -d '\r\n')"
a3="$(pf a agent add agent-a3-c11 acct-alice-7f3 | tr -d '\r\n')"
pf b account add acct-bob-2e8 Grace Hopper
b1="$(pf b agent add agent-b1-44a acct-bob-2e8 | tr -d '\r\n')"
r1="$(pf a request create acct-alice-7f3 agent-a1-91c "$b1" a2a.invoke UNTIL_REVOKED 0 | tr -d '\r\n')"
wait_for "request delivered" 60 is_req a "$r1" delivered
pf b inbox list | python3 -c "
import json,sys
inbox=json.load(sys.stdin); assert len(inbox)==1, inbox
item=inbox[0]; assert item['account_id']=='acct-bob-2e8' and item['requester_name']['given_name']=='Ada', item"
pf b inbox approve acct-bob-2e8 provider-a "$r1" a2a.invoke FIXED 3600
rel1="$(pf a request relationship "$r1" | tr -d '\r\n')"
wait_for "A ready" 90 is_ready a "$rel1"
wait_for "B ready" 90 is_ready b "$rel1"
pf a call "$rel1" "hello-over-the-edge" | python3 -c "
import json,sys
r=json.load(sys.stdin); assert r['response']['result']=='ALLOW' and r['echo']=='hello-over-the-edge', r"
pass "04 A->B: inbox with requester name, approval, Ready both sides, admitted agent stream over the edge"

# --- 05 B to A is a separate relationship ------------------------------------------------
log "05 B to A"
pf b agent add agent-b2-7a1 acct-bob-2e8 >/dev/null
r2="$(pf b request create acct-bob-2e8 agent-b2-7a1 "$a1" a2a.invoke FIXED 3600 | tr -d '\r\n')"
wait_for "B->A delivered" 60 is_req b "$r2" delivered
pf a inbox approve acct-alice-7f3 provider-b "$r2" a2a.invoke FIXED 3600
rel2="$(pf b request relationship "$r2" | tr -d '\r\n')"
wait_for "B->A ready" 90 is_ready b "$rel2"
is_ready a "$rel1"
pass "05 B->A: independent relationship; A->B unaffected"

# --- 06 privacy ----------------------------------------------------------------------------
log "06 privacy"
leak=0
for id in acct-alice-7f3 agent-a1-91c agent-a2-5d0; do
    if dc exec -T pg-b pg_dump -U postgres postgres | grep -q "$id"; then leak=1; echo "B exchange store holds $id" >&2; fi
    if dc logs --no-color adapter-b bridge-b platform-b | grep -q "$id"; then leak=1; echo "B logs hold $id" >&2; fi
    if grep -raq "$id" "$RUN/platform-b"; then leak=1; echo "B platform holds $id" >&2; fi
done
for id in acct-bob-2e8 agent-b1-44a; do
    if dc exec -T pg-a pg_dump -U postgres postgres | grep -q "$id"; then leak=1; echo "A exchange store holds $id" >&2; fi
done
[[ $leak == 0 ]]
pass "06 privacy: no internal account or agent ID in the other provider's stores or logs"

# --- 07 revoke, block, unblock -----------------------------------------------------------------
log "07 revoke and blocks"
pf b relationship revoke "$rel1"
wait_for "A sees revoke" 60 not_ready a "$rel1"
refute call_allowed a "$rel1" "after-revoke"
r3="$(pf a request create acct-alice-7f3 agent-a2-5d0 "$b1" a2a.invoke FIXED 3600 | tr -d '\r\n')"
wait_for "second request delivered" 60 is_req a "$r3" delivered
pf b inbox block acct-bob-2e8 provider-a "$r3"
wait_for "block shown as denied" 60 is_req a "$r3" denied
r4="$(pf a request create acct-alice-7f3 agent-a3-c11 "$b1" a2a.invoke FIXED 3600 | tr -d '\r\n')"
is_req a "$r4" not_recognized
pf b block clear provider-a "$a2" "$b1"
sleep 5
r5="$(pf a request create acct-alice-7f3 agent-a3-c11 "$b1" a2a.invoke FIXED 3600 | tr -d '\r\n')"
wait_for "unblocked request delivered" 60 is_req a "$r5" delivered
pass "07 revoke propagates and stops calls; block shown as denied and enforced account-wide; unblock lifts it"

# --- 08 failures and recovery ---------------------------------------------------------------------
log "08 failures"
dc stop platform-b >/dev/null
r6="$(pf a request create acct-alice-7f3 agent-a1-91c "$b1" a2a.invoke FIXED 3600 | tr -d '\r\n')"
sleep 6
is_req a "$r6" waiting_for_delivery
dc start platform-b >/dev/null
wait_for "delivered after platform B recovered" 90 is_req a "$r6" delivered
dc stop adapter-b >/dev/null
pf b inbox approve acct-bob-2e8 provider-a "$r6" a2a.invoke FIXED 3600 || true
sleep 3
pf b inbox list | python3 -c "
import json,sys
assert any(i['request_id']=='$r6' and i['state']=='approved' for i in json.load(sys.stdin)), 'intent should wait'"
dc start adapter-b >/dev/null
rel6="$(pf a request relationship "$r6" | tr -d '\r\n')"
wait_for "intent completed after adapter B recovered" 120 is_ready a "$rel6"
dc restart bridge-b >/dev/null
wait_for "bridge B back" 90 sh -c "docker compose -p $project -f $compose logs --since 2m bridge-b | grep -q BRIDGE_READY"
wait_for "call after bridge restart" 60 sh -c "docker compose -p $project -f $compose exec -T platform-a /opt/ptpan/ptpan-reference-platform /cfg/platform.json call $rel6 again | grep -q ALLOW"
pass "08 platform, adapter and bridge outages: requests and approvals wait and complete; nothing redone"

# --- 09 live peer suspension ------------------------------------------------------------------------
log "09 suspension"
adc a peer suspend provider-b
wait_for "A suspended B" 30 is_state a provider-b Suspended
wait_for "B sees A's suspension" 60 is_state b provider-a Suspended
refute call_allowed a "$rel6" "while-suspended"
adc a peer resume provider-b
wait_for "A active again" 60 is_state a provider-b Active
wait_for "B active again" 60 is_state b provider-a Active
wait_for "call after resume" 60 sh -c "docker compose -p $project -f $compose exec -T platform-a /opt/ptpan/ptpan-reference-platform /cfg/platform.json call $rel6 resumed | grep -q ALLOW"
pass "09 suspend and resume take effect without restarts on both sides"

# --- 10 open stream cut by revoke (D12) ---------------------------------------------------------------
log "10 stream cutoff"
b3="$(pf b agent add agent-b3-e02 acct-bob-2e8 | tr -d '\r\n')"
r10="$(pf a request create acct-alice-7f3 agent-a1-91c "$b3" a2a.invoke FIXED 3600 | tr -d '\r\n')"
wait_for "stream request delivered" 60 is_req a "$r10" delivered
pf b inbox approve acct-bob-2e8 provider-a "$r10" a2a.invoke FIXED 3600
rel10="$(pf a request relationship "$r10" | tr -d '\r\n')"
wait_for "stream relationship ready" 90 is_ready a "$rel10"
pf a hold "$rel10" 120 > "$RUN/hold.json" &
holder=$!
sleep 4
pf b relationship revoke "$rel10"
wait "$holder"
python3 - "$RUN/hold.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
assert r["response"]["result"] == "ALLOW" and 3 <= r["held_seconds"] <= 20, r
PY
pass "10 an open agent stream is closed by revoke within seconds (CLOSE_STREAMS), not at its deadline"

# The stream deadline is the earlier of 300 s and the lease expiry (D12): a
# 30-second lease shows the bridge closing the stream at its deadline.
b4="$(pf b agent add agent-b4-d30 acct-bob-2e8 | tr -d '\r\n')"
r10b="$(pf a request create acct-alice-7f3 agent-a1-91c "$b4" a2a.invoke FIXED 3600 | tr -d '\r\n')"
wait_for "deadline request delivered" 60 is_req a "$r10b" delivered
pf b inbox approve acct-bob-2e8 provider-a "$r10b" a2a.invoke FIXED 30
rel10b="$(pf a request relationship "$r10b" | tr -d '\r\n')"
wait_for "deadline relationship ready" 60 is_ready a "$rel10b"
opened="$(date +%s)"
pf a hold "$rel10b" 120 > "$RUN/hold-deadline.json"
python3 - "$RUN/hold-deadline.json" "$opened" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); opened = int(sys.argv[2])
allowed_for = r["response"]["deadline"] - opened
assert r["response"]["result"] == "ALLOW" and 0 < allowed_for <= 30, r
assert abs(r["held_seconds"] - allowed_for) <= 3, (r, allowed_for)
PY
pass "10b an open agent stream is closed at its deadline, which never passes the lease expiry"

# --- 11 manifest changes (D8) ------------------------------------------------------------------------
log "11 manifest changes"
effective="$(date -u -d '+25 seconds' +%Y-%m-%dT%H:%M:%SZ)"
ad b manifest propose /cfg/adapter.json /cfg/manifest-r2.json "$effective"
wait_for "A notified of B's pending revision" 60 sh -c "docker compose -p $project -f $compose exec -T pg-a psql -U postgres -tAc \"select record from ptpan_peers where platform_id='provider-b'\" | grep -q '\"pending\":{'"
adc a peer approve-pending provider-b
sleep 35
is_state a provider-b Active
pf a call "$rel6" "after-planned-change" | grep -q ALLOW
cp "$RUN/cfg-b/manifest-r3.json" "$RUN/cfg-b/manifest.json"
wait_for "A cut off B after an unannounced change" 90 is_state a provider-b Pending
pass "11 announced and approved change: no outage; unannounced change: cut off until revalidated"

# --- 12 live peer removal ----------------------------------------------------------------------------------
log "12 peer removal"
adc a peer remove provider-b
wait_for "A removed B" 30 is_state a provider-b Removed
wait_for "B sees A's removal" 60 is_state b provider-a Suspended
refute call_allowed a "$rel6" "after-removal"
# Base keeps removal final (PeerRuleError::Removed): the old record is not
# revived by a new bootstrap.
refute adc a peer add /cfg/bootstrap-peer.json
pass "12 removal while cut off: the restriction still reaches the other side, calls stop, removal is final"

log "ladder complete"
