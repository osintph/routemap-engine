#!/usr/bin/env bash
# A per-flow load balancer in Linux network namespaces, for the live path
# discovery test (tests/test_multipath_live.py). CI only (root, a throwaway
# runner). Two equal paths from the runner to one target, IPv4 and IPv6:
#
#   runner --- prt --+-- pa --+-- ptg (10.78.9.9, fd78:9::9)
#                    +-- pb --+
#
# prt chooses pa or pb per flow: nftables hashes source, destination and the
# ICMP identifier and checksum (the fields Paris traceroute holds per flow),
# marks the packet, and policy routing sends mark 0 to pa, mark 1 to pb.
# ICMP rate limits are off in every namespace so no answer is held back.
set -euo pipefail
command -v nft >/dev/null || sudo apt-get install -y -qq nftables >/dev/null
ns() { sudo ip netns exec "$@"; }
for n in prt pa pb ptg; do sudo ip netns add $n; ns $n ip link set lo up
  ns $n sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 \
    net.ipv4.icmp_ratelimit=0 net.ipv6.icmp.ratelimit=0 net.ipv6.conf.all.accept_dad=0 \
    net.ipv6.conf.default.accept_dad=0; done
link() {  # link NS_A IF_A NS_B IF_B  (NS "-" is the runner)
  sudo ip link add "$2" type veth peer name "$4"
  [ "$1" != - ] && sudo ip link set "$2" netns "$1"; sudo ip link set "$4" netns "$3"
  if [ "$1" = - ]; then sudo ip link set "$2" up; else ns "$1" ip link set "$2" up; fi
  ns "$3" ip link set "$4" up; }
addr() { if [ "$1" = - ]; then sudo ip addr add "$3" dev "$2"; else ns "$1" ip addr add "$3" dev "$2"; fi; }
sudo sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0
link - ph0 prt pr0;  addr - ph0 10.78.0.1/24;  addr - ph0 fd78:0::1/64;  addr prt pr0 10.78.0.2/24; addr prt pr0 fd78:0::2/64
link prt pra pa pa0; addr prt pra 10.78.2.1/24; addr prt pra fd78:2::1/64; addr pa pa0 10.78.2.2/24; addr pa pa0 fd78:2::2/64
link prt prb pb pb0; addr prt prb 10.78.3.1/24; addr prt prb fd78:3::1/64; addr pb pb0 10.78.3.2/24; addr pb pb0 fd78:3::2/64
link pa pat ptg pt0; addr pa pat 10.78.4.1/24;  addr pa pat fd78:4::1/64;  addr ptg pt0 10.78.4.2/24; addr ptg pt0 fd78:4::2/64
link pb pbt ptg pt1; addr pb pbt 10.78.5.1/24;  addr pb pbt fd78:5::1/64;  addr ptg pt1 10.78.5.2/24; addr ptg pt1 fd78:5::2/64
ns ptg ip addr add 10.78.9.9/32 dev lo; ns ptg ip addr add fd78:9::9/128 dev lo
# Runner: the lab prefixes via prt.
sudo ip route add 10.78.0.0/16 via 10.78.0.2; sudo ip -6 route add fd78::/16 via fd78:0::2
# prt: per-flow choice for the target, by mark.
ns prt nft -f - <<'NFT'
table inet paths {
  chain pre {
    type filter hook prerouting priority mangle; policy accept;
    ip daddr 10.78.9.9 ip protocol icmp meta mark set jhash ip saddr . ip daddr . icmp id . icmp checksum mod 2 seed 0x5a5a
    ip6 daddr fd78:9::9 meta l4proto ipv6-icmp meta mark set jhash ip6 saddr . ip6 daddr . icmpv6 id . icmpv6 checksum mod 2 seed 0x5a5a
  }
}
NFT
for fam in "" "-6"; do
  ns prt ip $fam rule add fwmark 0 lookup 100; ns prt ip $fam rule add fwmark 1 lookup 101; done
ns prt ip route add 10.78.9.9/32 via 10.78.2.2 table 100; ns prt ip route add 10.78.9.9/32 via 10.78.3.2 table 101
ns prt ip -6 route add fd78:9::9/128 via fd78:2::2 table 100; ns prt ip -6 route add fd78:9::9/128 via fd78:3::2 table 101
ns prt ip route add 10.78.9.9/32 via 10.78.2.2; ns prt ip -6 route add fd78:9::9/128 via fd78:2::2
# pa, pb: on to the target, back to the runner.
ns pa ip route add 10.78.9.9/32 via 10.78.4.2;  ns pa ip -6 route add fd78:9::9/128 via fd78:4::2
ns pa ip route add 10.78.0.0/24 via 10.78.2.1;  ns pa ip -6 route add fd78:0::/64 via fd78:2::1
ns pb ip route add 10.78.9.9/32 via 10.78.5.2;  ns pb ip -6 route add fd78:9::9/128 via fd78:5::2
ns pb ip route add 10.78.0.0/24 via 10.78.3.1;  ns pb ip -6 route add fd78:0::/64 via fd78:3::1
# ptg: answers go back through pa.
ns ptg ip route add default via 10.78.4.1; ns ptg ip -6 route add default via fd78:4::1
sleep 1
ping -c1 -W2 10.78.9.9 >/dev/null && ping -6 -c1 -W2 fd78:9::9 >/dev/null && echo "paths lab ready"
