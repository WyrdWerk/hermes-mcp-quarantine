#!/usr/bin/env bash
# netns-up.sh — isolated network namespace with outbound NAT.
# Idempotent: safe to run on every audit. Needs sudo -n (the InstaBox exec user
# is not root). Installs the tools it needs only when they are missing, so a
# prebuilt snapshot pays nothing.
set -u
S="sudo -n"
NS=audit
HOST_IP=10.200.0.1
NS_IP=10.200.0.2

need=""
for b in ip iptables sysctl tcpdump strace setpriv; do
  command -v "$b" >/dev/null 2>&1 || [ -x "/usr/sbin/$b" ] || [ -x "/usr/bin/$b" ] || need="$need $b"
done
if [ -n "$need" ]; then
  echo "installing:$need"
  export DEBIAN_FRONTEND=noninteractive
  $S apt-get -qq update >/dev/null 2>&1
  $S apt-get -qq install -y iproute2 iptables procps tcpdump strace util-linux >/dev/null 2>&1
fi

UP=$(ip -4 route show default | awk '{print $5; exit}')
[ -n "$UP" ] || { echo "no default route" >&2; exit 1; }

$S ip netns del "$NS" 2>/dev/null
$S ip link del veth-h 2>/dev/null
$S ip netns add "$NS" || exit 1
$S mkdir -p /etc/netns/$NS
# Public resolvers only. Copying the host resolv.conf would send DNS to the
# provider's private resolver, which the RFC1918 DROP below would then block.
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' | $S tee /etc/netns/$NS/resolv.conf >/dev/null
$S ip link add veth-h type veth peer name veth-a
$S ip link set veth-a netns "$NS"
$S ip addr add $HOST_IP/24 dev veth-h
$S ip link set veth-h up
$S ip netns exec "$NS" ip addr add $NS_IP/24 dev veth-a
$S ip netns exec "$NS" ip link set veth-a up
$S ip netns exec "$NS" ip link set lo up
$S ip netns exec "$NS" ip route add default via $HOST_IP
$S sysctl -qw net.ipv4.ip_forward=1
# Reset any rules from a previous run so the counters and the path are known.
$S iptables -t nat -D POSTROUTING -s 10.200.0.0/24 -o "$UP" -j MASQUERADE 2>/dev/null
$S iptables -D FORWARD -i veth-h -o "$UP" -j ACCEPT 2>/dev/null
$S iptables -D FORWARD -i "$UP" -o veth-h -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
$S iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -o "$UP" -j MASQUERADE
$S iptables -A FORWARD -i veth-h -o "$UP" -j ACCEPT
$S iptables -A FORWARD -i "$UP" -o veth-h -m state --state RELATED,ESTABLISHED -j ACCEPT
# The namespace is not a sandbox for the host. Block cloud metadata, the
# InstaBox /30, and other private ranges so the target cannot reach host
# services or IMDS over NAT. INPUT on veth-h drops packets aimed at 10.200.0.1.
for d in 169.254.0.0/16 172.16.0.0/12 10.0.0.0/8 192.168.0.0/16 100.64.0.0/10 127.0.0.0/8; do
  $S iptables -I FORWARD -i veth-h -d "$d" -j DROP
done
$S iptables -I INPUT -i veth-h -j DROP
if command -v ip6tables >/dev/null 2>&1 || [ -x /usr/sbin/ip6tables ]; then
  $S ip6tables -I FORWARD -i veth-h -j DROP 2>/dev/null || true
  $S ip6tables -I INPUT -i veth-h -j DROP 2>/dev/null || true
fi

code=$($S ip netns exec "$NS" curl -sS -o /dev/null -w '%{http_code}' --max-time 8 https://registry.npmjs.org/ 2>/dev/null || echo FAIL)
echo "uplink=$UP netns_http=$code"
[ "$code" = "200" ] || exit 1
