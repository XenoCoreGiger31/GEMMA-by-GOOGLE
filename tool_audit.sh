#!/usr/bin/env bash
# HALO tool-manifest audit — RUN THIS ON THE UBUNTU HOST THAT EXECUTES ENGAGEMENTS (deddy).
#
# For every tool binary the agent expects, it reports:
#   - resolvable?  (mimics resolve_tool: PATH first, then ~/go/bin ~/.local/bin /usr/local/bin /usr/bin)
#   - architecture (via `file` — catches the Go/Debian case: an arm64/other-distro binary)
#   - does it actually RUN? (catches "exec format error" — which resolve_tool() cannot detect,
#     because it only checks the file exists + is executable)
#
# Throwaway diagnostic — delete after, or it'll get gitignored before the next commit.

set -u
DIRS=("$HOME/go/bin" "$HOME/.local/bin" "/usr/local/bin" "/usr/bin")

# The real binary each of the 28 tools invokes (run_command/run_exploit have no external
# binary — bash and the podman sandbox — so they're excluded).
BINS="nmap masscan hydra medusa ncrack john nikto enum4linux sqlmap searchsploit \
msfconsole nuclei httpx katana subfinder ffuf gobuster wafw00f sherlock \
phoneinfoga cloudfox shodan curl wget netstat ss setoolkit"

resolve() {  # PATH first, then resolve_tool's extra dirs
  local n="$1" p
  p="$(command -v "$n" 2>/dev/null)" && { echo "$p"; return 0; }
  for d in "${DIRS[@]}"; do
    [ -x "$d/$n" ] && { echo "$d/$n"; return 0; }
  done
  return 1
}

printf "%-13s %-8s %-30s %s\n" TOOL STATUS PATH "ARCH / NOTE"
printf '%.0s-' $(seq 1 96); echo
ok=0; missing=0; broken=0
for b in $BINS; do
  path="$(resolve "$b")"
  if [ -z "$path" ]; then
    printf "%-13s %-8s %-30s %s\n" "$b" "MISSING" "-" "not installed / not on PATH or known dirs"
    missing=$((missing+1)); continue
  fi
  arch="$(file -b "$path" 2>/dev/null | cut -c1-46)"
  # exec probe — try the common version flags, then --help. We only care whether the
  # kernel/loader can run it at all; "exec format error" = wrong arch = the Debian problem.
  out="$(timeout 8 "$path" --version 2>&1 </dev/null | head -1)"
  [ -z "$out" ] && out="$(timeout 8 "$path" -version 2>&1 </dev/null | head -1)"
  [ -z "$out" ] && out="$(timeout 8 "$path" --help 2>&1 </dev/null | head -1)"
  if echo "$arch $out" | grep -qiE "exec format error|cannot execute"; then
    printf "%-13s %-8s %-30s %s\n" "$b" "BROKEN" "$path" "$arch"
    broken=$((broken+1))
  else
    printf "%-13s %-8s %-30s %s\n" "$b" "OK" "$path" "$arch"
    ok=$((ok+1))
  fi
done
echo
echo "SUMMARY:  OK=$ok  MISSING=$missing  BROKEN=$broken"
echo
echo "=== deddy tool manifest count (Mac build has 28) ==="
grep -cE '^[[:space:]]*\{"name": "run_' "$HOME/GEMMA-by-GOOGLE/halo_tools.py" 2>/dev/null \
  || echo "halo_tools.py not found at ~/GEMMA-by-GOOGLE"
echo "=== deddy tool names (diff against Mac to find the divergence) ==="
grep -oE '"name": "run_[a-z0-9_]+"' "$HOME/GEMMA-by-GOOGLE/halo_tools.py" 2>/dev/null | sort
