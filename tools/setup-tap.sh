#!/usr/bin/env bash
set -euo pipefail

# Isolated IPv4 NAT for the ESP32 emulator's real ICMP/TCP/UDP tests.
tap=nm-esp-tap
subnet=192.168.4.0/24
gateway=192.168.4.1/24
# Preserve LAN split-DNS rather than resolving dev services through public DNS.
dns=${NM_ESP_DNS:-$(awk '/^nameserver / && $2 ~ /^[0-9.]+$/ && $2 !~ /^127\./ { print $2; exit }' /etc/resolv.conf)}
if [[ -z $dns ]] || ! python3 -c 'import ipaddress,sys; a=ipaddress.IPv4Address(sys.argv[1]); sys.exit(a.is_loopback or a.is_unspecified or a.is_multicast)' "$dns"; then
    echo 'Set NM_ESP_DNS to a reachable IPv4 DNS resolver, not a loopback stub.' >&2
    exit 1
fi

if [[ ${EUID} -ne 0 ]]; then
    echo 'Run this script with sudo.' >&2
    exit 1
fi
if [[ $# -gt 1 || ( $# -eq 1 && $1 != --teardown ) ]]; then
    echo 'Usage: sudo tools/setup-tap.sh [--teardown]' >&2
    exit 1
fi
owner=${SUDO_USER:-}
if [[ -z $owner || $owner == root ]]; then
    echo 'Run via sudo as the user who will run esp-emu.' >&2
    exit 1
fi
outbound=$(ip -4 route show default | awk 'NR == 1 { for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }')
if [[ -z $outbound ]]; then
    echo 'No default IPv4 interface found.' >&2
    exit 1
fi

forward_out=(-i "$tap" -o "$outbound" -s "$subnet" -j ACCEPT)
forward_back=(-i "$outbound" -o "$tap" -d "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT)
masquerade=(-s "$subnet" -o "$outbound" -j MASQUERADE)
dns_route=(-i "$tap" -s "$subnet" -d 8.8.8.8 -p udp --dport 53 -j DNAT --to-destination "$dns:53")

if [[ ${1:-} == --teardown ]]; then
    /usr/sbin/iptables -t nat -D PREROUTING "${dns_route[@]}" 2>/dev/null || true
    /usr/sbin/iptables -D FORWARD "${forward_out[@]}" 2>/dev/null || true
    /usr/sbin/iptables -D FORWARD "${forward_back[@]}" 2>/dev/null || true
    /usr/sbin/iptables -t nat -D POSTROUTING "${masquerade[@]}" 2>/dev/null || true
    if ip link show dev "$tap" &>/dev/null; then
        ip link set dev "$tap" down
        ip tuntap del dev "$tap" mode tap
    fi
    echo "Removed $tap and its NAT rules."
    exit 0
fi

if ip link show dev "$tap" &>/dev/null; then
    if ! ip -d link show dev "$tap" | grep -q 'tun type tap'; then
        echo "$tap exists but is not a TAP device; refusing to change it." >&2
        exit 1
    fi
else
    ip tuntap add dev "$tap" mode tap user "$owner"
fi
if ! ip -4 addr show dev "$tap" | grep -q 'inet 192\.168\.4\.1/24'; then
    ip addr add "$gateway" dev "$tap"
fi
ip link set dev "$tap" up
if [[ $(cat /proc/sys/net/ipv4/ip_forward) != 1 ]]; then
    /usr/sbin/sysctl -q net.ipv4.ip_forward=1
fi
/usr/sbin/iptables -C FORWARD "${forward_out[@]}" 2>/dev/null ||
    /usr/sbin/iptables -I FORWARD 1 "${forward_out[@]}"
/usr/sbin/iptables -C FORWARD "${forward_back[@]}" 2>/dev/null ||
    /usr/sbin/iptables -I FORWARD 1 "${forward_back[@]}"
/usr/sbin/iptables -t nat -C POSTROUTING "${masquerade[@]}" 2>/dev/null ||
    /usr/sbin/iptables -t nat -I POSTROUTING 1 "${masquerade[@]}"
/usr/sbin/iptables -t nat -C PREROUTING "${dns_route[@]}" 2>/dev/null ||
    /usr/sbin/iptables -t nat -I PREROUTING 1 "${dns_route[@]}"
echo "$tap ready: $subnet via $outbound, DNS $dns (owner $owner)."
