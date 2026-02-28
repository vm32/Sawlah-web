#!/usr/bin/env bash
set -e

RED='\033[1;31m'
GRN='\033[1;32m'
DIM='\033[0;90m'
BLD='\033[1;37m'
RST='\033[0m'

banner() {
  echo -e "${RED}"
  echo "  ███████╗ █████╗ ██╗    ██╗██╗      █████╗ ██╗  ██╗"
  echo "  ██╔════╝██╔══██╗██║    ██║██║     ██╔══██╗██║  ██║"
  echo "  ███████╗███████║██║ █╗ ██║██║     ███████║███████║"
  echo "  ╚════██║██╔══██║██║███╗██║██║     ██╔══██║██╔══██║"
  echo "  ███████║██║  ██║╚███╔███╔╝███████╗██║  ██║██║  ██║"
  echo "  ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝"
  echo -e "${DIM}  Penetration Testing Web Panel — Installer${RST}"
  echo ""
}

info()  { echo -e "  ${GRN}[+]${RST} $1"; }
warn()  { echo -e "  ${RED}[!]${RST} $1"; }

INSTALL_DIR="${SAWLAH_DIR:-$HOME/Sawlah-web}"
REPO="https://github.com/vm32/Sawlah-web.git"

cleanup() {
  info "Shutting down..."
  [ -n "$BACK_PID" ]  && kill "$BACK_PID"  2>/dev/null
  [ -n "$FRONT_PID" ] && kill "$FRONT_PID" 2>/dev/null
  wait 2>/dev/null
  exit 0
}
trap cleanup INT TERM

banner

# ── Check prerequisites ───────────────────────────────────────
MISSING=""
command -v git     >/dev/null || MISSING="$MISSING git"
command -v python3 >/dev/null || MISSING="$MISSING python3"
command -v pip3    >/dev/null || MISSING="$MISSING python3-pip"
command -v node    >/dev/null || MISSING="$MISSING nodejs"
command -v npm     >/dev/null || MISSING="$MISSING npm"

if [ -n "$MISSING" ]; then
  warn "Missing packages:${RED}$MISSING${RST}"
  info "Installing with apt..."
  sudo apt update -qq && sudo apt install -y -qq $MISSING
fi

# ── Clone or update ───────────────────────────────────────────
if [ -d "$INSTALL_DIR/.git" ]; then
  info "Sawlah-web found at ${BLD}$INSTALL_DIR${RST} — pulling latest..."
  git -C "$INSTALL_DIR" pull --ff-only 2>/dev/null || true
else
  info "Cloning Sawlah-web to ${BLD}$INSTALL_DIR${RST} ..."
  git clone "$REPO" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# ── Backend deps ──────────────────────────────────────────────
info "Installing Python dependencies..."
pip3 install -q --break-system-packages -r backend/requirements.txt 2>/dev/null \
  || pip3 install -q -r backend/requirements.txt

# ── Frontend deps ─────────────────────────────────────────────
if [ ! -d "frontend/node_modules" ]; then
  info "Installing Node dependencies (first run)..."
  npm install --prefix frontend --silent
else
  info "Node dependencies already installed."
fi

# ── Start backend ─────────────────────────────────────────────
info "Starting backend on http://127.0.0.1:8000 ..."
cd backend
python3 main.py &
BACK_PID=$!
cd "$INSTALL_DIR"

sleep 2
if ! kill -0 "$BACK_PID" 2>/dev/null; then
  warn "Backend failed to start. Check errors above."
  exit 1
fi

# ── Start frontend ────────────────────────────────────────────
info "Starting frontend on http://localhost:3000 ..."
npm run dev --prefix frontend &
FRONT_PID=$!

sleep 3

echo ""
info "Sawlah-web is running!"
echo -e "  ${DIM}──────────────────────────────────────${RST}"
echo -e "  ${GRN}Panel${RST}   → ${RED}http://localhost:3000${RST}"
echo -e "  ${GRN}API${RST}     → ${DIM}http://127.0.0.1:8000${RST}"
echo -e "  ${GRN}Folder${RST}  → ${DIM}$INSTALL_DIR${RST}"
echo -e "  ${DIM}──────────────────────────────────────${RST}"
echo -e "  Press ${RED}Ctrl+C${RST} to stop both servers."
echo ""

wait
