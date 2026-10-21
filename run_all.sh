#!/usr/bin/env bash
# ==============================================================================
# run_all.sh
# Starts both PCAP Analyzer servers:
#   - Backend: FastAPI on http://localhost:8000
#   - Frontend: Vite React on http://localhost:5173
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo " Starting PCAP Analyzer Platform"
echo " Backend:  http://localhost:8000"
echo " Frontend: http://localhost:5173"
echo "============================================================"

# Ensure virtual environment is activated
if [ -d ".venv" ]; then
    source .venv/bin/activate
else
    echo "[!] Error: .venv virtual environment not found in $SCRIPT_DIR"
    exit 1
fi

# Clean up any existing processes on ports 8000 and 5173
echo "[*] Ensuring ports 8000 and 5173 are available..."
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
lsof -ti:5173 | xargs kill -9 2>/dev/null || true

# Start FastAPI backend in background
echo "[*] Launching FastAPI backend on port 8000..."
uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Trap signals to ensure backend is killed when script terminates
cleanup() {
    echo ""
    echo "[*] Shutting down servers..."
    kill $BACKEND_PID 2>/dev/null || true
    lsof -ti:8000 | xargs kill -9 2>/dev/null || true
    lsof -ti:5173 | xargs kill -9 2>/dev/null || true
    echo "[+] Done."
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# Wait briefly for backend to become ready
echo "[*] Waiting for backend readiness..."
for i in {1..20}; do
    if curl -s http://localhost:8000/api/health >/dev/null 2>&1; then
        echo "[+] Backend is healthy."
        break
    fi
    sleep 0.5
done

# Start frontend in foreground
echo "[*] Launching Vite React frontend on port 5173..."
cd "$SCRIPT_DIR/frontend"
npm run dev -- --host 0.0.0.0 --port 5173
