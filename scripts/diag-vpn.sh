#!/usr/bin/env bash
# diag-vpn.sh — capture routing/firewall/connectivity state for diagnosing the
# SOCKS5-proxy + WireGuard/Mullvad interaction.
#
# Usage:
#   scripts/diag-vpn.sh <label> [proxy_host] [proxy_port]
#
# Examples:
#   scripts/diag-vpn.sh baseline           # VPN off, proxy off  (reference)
#   scripts/diag-vpn.sh wg-only            # WireGuard up, proxy off
#   scripts/diag-vpn.sh wg-proxy           # WireGuard up, proxy on  (failure)
#
# Run it in whatever state you want to snapshot. It writes everything into
# ./diag/<timestamp>-<label>/ and never needs the network to come back for me
# to read it. Some captures need root; the script uses `sudo -n` and notes when
# a capture was skipped for lack of privileges.

set -u

LABEL="${1:-snapshot}"
PROXY_HOST="${2:-res.proxy-seller.com}"
PROXY_PORT="${3:-10000}"

# The physical default-route interface (lowest metric, not a VPN/TUN). This is
# the same selection the daemon's `physical_default_gateway()` makes — derived,
# never hard-coded, so it tracks whatever uplink is actually up (eth, wlan,
# wwan, …). Override with CLAUDE_IFACE=<name> if needed.
detect_physical_iface() {
  ip -4 route show default 2>/dev/null | awk '
    {
      dev=""; metric=999999;
      for (i = 1; i <= NF; i++) {
        if ($i == "dev") dev = $(i + 1);
        if ($i == "metric") metric = $(i + 1);
      }
      if (dev == "") next;
      if (dev ~ /^(tun|tap|wg|vpn|ppp|utun|tailscale|nordlynx|warp|zt|proton)/) next;
      if (dev ~ /^s5p/) next;
      print metric, dev;
    }' | sort -n | awk 'NR==1 {print $2}'
}
CLAUDE_IFACE="${CLAUDE_IFACE:-$(detect_physical_iface)}"
CLAUDE_IFACE="${CLAUDE_IFACE:-unknown}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$ROOT/diag/$TS-$LABEL"
mkdir -p "$OUT"

run() { # run <outfile> -- <command...>
  local f="$OUT/$1"; shift
  [ "$1" = "--" ] && shift
  {
    echo "# \$ $*"
    echo "# ---"
    "$@" 2>&1
    echo "# (exit $?)"
  } >"$f"
}
srun() { # same but via sudo -n; marks if no privileges
  local f="$OUT/$1"; shift
  [ "$1" = "--" ] && shift
  {
    echo "# \$ sudo $*"
    echo "# ---"
    if sudo -n true 2>/dev/null; then
      sudo "$@" 2>&1
      echo "# (exit $?)"
    else
      echo "# SKIPPED: no passwordless sudo. Re-run as: sudo $0 $LABEL"
    fi
  } >"$f"
}

echo "capturing -> $OUT"

# --- context ----------------------------------------------------------------
{
  echo "label:       $LABEL"
  echo "timestamp:   $TS"
  echo "proxy:       $PROXY_HOST:$PROXY_PORT"
  echo "claude_iface:$CLAUDE_IFACE"
  echo "user:        $(id)"
  echo "kernel:      $(uname -a)"
} >"$OUT/00-context.txt"

# Resolve proxy host -> IP(s) for route/reachability checks.
PROXY_IPS="$(getent ahosts "$PROXY_HOST" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')"
echo "proxy_ips:   $PROXY_IPS" >>"$OUT/00-context.txt"
PROXY_IP1="$(echo $PROXY_IPS | awk '{print $1}')"

# --- interfaces & addressing ------------------------------------------------
run 10-links.txt        -- ip -o link show
run 11-addrs.txt        -- ip -o addr show
srun 12-wg.txt          -- wg show

# --- routing ----------------------------------------------------------------
run 20-route-default.txt -- ip route show default
run 21-route-all.txt     -- ip route show table all
run 22-rules.txt         -- ip rule show
# Where does the kernel send each class of destination?
{
  for tgt in 1.1.1.1 8.8.8.8 192.168.0.1 "$CLAUDE_IFACE-gw" $PROXY_IPS; do
    [ "$tgt" = "$CLAUDE_IFACE-gw" ] && continue
    echo "## ip route get $tgt"
    ip route get "$tgt" 2>&1
    echo
  done
} >"$OUT/23-route-get.txt"

# --- firewall ---------------------------------------------------------------
srun 30-nft.txt          -- nft list ruleset
srun 31-iptables.txt     -- iptables-save
srun 32-iptables-legacy.txt -- iptables-legacy-save

# --- processes & sockets ----------------------------------------------------
run 40-procs.txt -- bash -c "ps -eo pid,ppid,user,comm,args | grep -Ei 'tun2proxy|socks5proxy|wg-quick|wireguard' | grep -v grep"
srun 41-sockets.txt -- ss -tunap

# --- daemon logs (if the systemd unit exists) -------------------------------
if systemctl list-unit-files 2>/dev/null | grep -qi socks5proxyd; then
  sun_since="-1 hour"
  srun 50-journal-daemon.txt -- journalctl -u socks5proxyd --since "$sun_since" --no-pager
fi

# --- DNS --------------------------------------------------------------------
run 60-resolv.txt   -- cat /etc/resolv.conf
run 61-resolvectl.txt -- resolvectl status

# --- connectivity probes ----------------------------------------------------
{
  echo "## raw WAN via default route (curl https://1.1.1.1, 5s)"
  curl -m5 -sS -o /dev/null -w 'http=%{http_code} time=%{time_total}s\n' https://1.1.1.1 2>&1 || echo "FAILED"
  echo
  echo "## who am I to the internet (api.ipify.org, direct, 5s)"
  curl -m5 -sS https://api.ipify.org 2>&1 || echo "FAILED"; echo
  echo
  echo "## reach proxy server TCP $PROXY_HOST:$PROXY_PORT (nc -z, 5s)"
  if [ -n "$PROXY_IP1" ]; then
    nc -z -w5 "$PROXY_IP1" "$PROXY_PORT" 2>&1 && echo "OPEN" || echo "CLOSED/UNREACHABLE"
  else
    echo "no resolved proxy IP"
  fi
  echo
  echo "## exit IP *through* the SOCKS5 proxy (curl --socks5-hostname, 10s)"
  echo "   (anonymous; will show auth error if creds required — that still proves reachability)"
  curl -m10 -sS --socks5-hostname "$PROXY_HOST:$PROXY_PORT" https://api.ipify.org 2>&1 || echo "FAILED"; echo
  echo
  echo "## ping proxy IP (3x)"
  [ -n "$PROXY_IP1" ] && ping -c3 -W2 "$PROXY_IP1" 2>&1 || echo "no IP / unreachable"
} >"$OUT/70-connectivity.txt" 2>&1

# --- conntrack (optional) ---------------------------------------------------
command -v conntrack >/dev/null && srun 80-conntrack.txt -- conntrack -L

echo "done. share: $OUT"
ls -1 "$OUT"
