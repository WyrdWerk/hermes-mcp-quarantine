#!/usr/bin/env bash
# run-target.sh NAME IDLE_SECONDS 'COMMAND' — run COMMAND inside the netns while
# capturing every packet on the host side of the veth pair and every file and
# connect syscall via strace.
#
# The target is not root. ip netns exec would otherwise run as root because it
# is invoked with sudo; setpriv drops to the exec user and clears capabilities
# before strace starts. tcpdump stays root on the host veth (observer only).
#
# -s 0 is mandatory: the post-quantum ClientHello is ~1.6 KB, so a short snaplen
# truncates the SNI away and every TLS host becomes an IP-only row.
set -u
NAME=$1; IDLE=$2; CMD=$3
mkdir -p /tmp/cap /tmp/work
PC=/tmp/cap/$NAME.pcap
rm -f "$PC" /tmp/cap/$NAME.strace /tmp/cap/$NAME.out

SETPRIV=$(command -v setpriv || true)
[ -n "$SETPRIV" ] || SETPRIV=/usr/bin/setpriv
if [ ! -x "$SETPRIV" ]; then
  echo "setpriv missing; refusing to run the target as root" >&2
  exit 1
fi
AUDIT_UID=$(id -u)
AUDIT_GID=$(id -g)

sudo -n tcpdump -i veth-h -s 0 -w "$PC" -U >/tmp/cap/$NAME.tcpdump.log 2>&1 &
TP=$!
sleep 1.5
S=$(date +%s%N)
# The cache overrides go *inside* the login shell: /etc/profile.d/instabox-npm.sh
# points npm's cache at /data/tmp, which survives into a snapshot and would make a
# repeat install look like 10 kB instead of 4 MB. Exports before bash -lc are
# overwritten by that profile script.
sudo -n ip netns exec audit "$SETPRIV" \
  --reuid="$AUDIT_UID" --regid="$AUDIT_GID" --clear-groups \
  --inh-caps=-all --ambient-caps=-all --no-new-privs \
  strace -f -e trace=file,network -s 200 \
  -o /tmp/cap/$NAME.strace bash -lc "cd /tmp/work \
  && export npm_config_cache=/tmp/work/.npm-cache npm_config_update_notifier=false \
     NO_UPDATE_NOTIFIER=1 PIP_NO_CACHE_DIR=1 \
  && $CMD" >/tmp/cap/$NAME.out 2>&1
RC=$?
E=$(date +%s%N)
sleep "$IDLE"
sudo -n kill -INT "$TP" 2>/dev/null; sleep 1.5; sudo -n kill -9 "$TP" 2>/dev/null
cat > /tmp/cap/$NAME.meta <<EOF
{"name":"$NAME","exit":$RC,"wall_ms":$(( (E-S)/1000000 )),"idle_seconds":$IDLE,"pcap_bytes":$(stat -c%s "$PC" 2>/dev/null || echo 0)}
EOF
echo "phase=$NAME rc=$RC wall_ms=$(( (E-S)/1000000 )) pcap=$(stat -c%s "$PC" 2>/dev/null)"
