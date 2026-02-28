#!/usr/bin/env bash
set -e

RED='\033[1;31m'
GRN='\033[1;32m'
DIM='\033[0;90m'
RST='\033[0m'

banner() {
  echo -e "${RED}"
  echo "  ███████╗ █████╗ ██╗    ██╗██╗      █████╗ ██╗  ██╗"
  echo "  ██╔════╝██╔══██╗██║    ██║██║     ██╔══██╗██║  ██║"
  echo "  ███████╗███████║██║ █╗ ██║██║     ███████║███████║"
  echo "  ╚════██║██╔══██║██║███╗██║██║     ██╔══██║██╔══██║"
  echo "  ███████║██║  ██║╚███╔███╔╝███████╗██║  ██║██║  ██║"
  echo "  ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝"
  echo -e "${DIM}  Penetration Testing Web Panel${RST}"
  echo ""
}

info()  { echo -e "  ${GRN}[+]${RST} $1"; }
err()   { echo -e "  ${RED}[!]${RST} $1"; }

ROOT="$(cd "$(dirname "$0")" && pwd)"

cleanup() {
  info "Shutting down..."
  [ -n "$BACK_PID" ] && kill "$BACK_PID" 2>/dev/null
  [ -n "$FRONT_PID" ] && kill "$FRONT_PID" 2>/dev/null
  wait 2>/dev/null
  exit 0
}
trap cleanup INT TERM

banner

# ── Prerequisites ──────────────────────────────────────────────
command -v python3 >/dev/null || { err "python3 not found. Install it first."; exit 1; }
command -v node    >/dev/null || { err "node not found. Run: sudo apt install nodejs npm"; exit 1; }
command -v npm     >/dev/null || { err "npm not found. Run: sudo apt install npm"; exit 1; }

# ── Backend deps ───────────────────────────────────────────────
info "Installing Python dependencies..."
pip3 install -q --break-system-packages -r "$ROOT/backend/requirements.txt" 2>/dev/null \
  || pip3 install -q -r "$ROOT/backend/requirements.txt"

# ── Frontend deps ──────────────────────────────────────────────
if [ ! -d "$ROOT/frontend/node_modules" ]; then
  info "Installing Node dependencies (first run)..."
  npm install --prefix "$ROOT/frontend" --silent
else
  info "Node dependencies already installed."
fi

# ── Start backend ──────────────────────────────────────────────
info "Starting backend on http://127.0.0.1:8000 ..."
cd "$ROOT/backend"
python3 main.py &
BACK_PID=$!
cd "$ROOT"

sleep 2

if ! kill -0 "$BACK_PID" 2>/dev/null; then
  err "Backend failed to start. Check errors above."
  exit 1
fi

# ── Start frontend ─────────────────────────────────────────────
info "Starting frontend on http://localhost:3000 ..."
npm run dev --prefix "$ROOT/frontend" &
FRONT_PID=$!

sleep 3

echo ""
info "Sawlah-web is running!"
echo -e "  ${DIM}──────────────────────────────────────${RST}"
echo -e "  ${GRN}Panel${RST}   → ${RED}http://localhost:3000${RST}"
echo -e "  ${GRN}API${RST}     → ${DIM}http://127.0.0.1:8000${RST}"
echo -e "  ${DIM}──────────────────────────────────────${RST}"
echo -e "  Press ${RED}Ctrl+C${RST} to stop both servers."
echo ""

wait
