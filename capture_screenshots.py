#!/usr/bin/env python3
"""
capture_screenshots.py
Automates capturing 14 crisp, retina-quality screenshots of the WireScope React app.
Uses Playwright (sync API, headless Chromium, viewport 1600x1000, device_scale_factor=2).
"""

import os
import sys
import time
import glob
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

BACKEND_URL = "http://localhost:8000/api/health"
FRONTEND_URL = "http://localhost:5173"
REPO_ROOT = Path(__file__).resolve().parent
SCREENSHOTS_DIR = REPO_ROOT / "screenshots"

def wait_for_services(timeout=60):
    print("[*] Verifying backend and frontend availability...")
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        backend_ok = False
        frontend_ok = False
        try:
            with urllib.request.urlopen(BACKEND_URL, timeout=2) as resp:
                if resp.status == 200:
                    backend_ok = True
        except Exception:
            pass
            
        try:
            with urllib.request.urlopen(FRONTEND_URL, timeout=2) as resp:
                if resp.status == 200:
                    frontend_ok = True
        except Exception:
            pass
            
        if backend_ok and frontend_ok:
            print("[+] Both backend and frontend services are responding.")
            return True
            
        print(f"    Waiting for services... (backend: {backend_ok}, frontend: {frontend_ok})")
        time.sleep(1.5)
        
    print("[!] Timeout waiting for services.")
    return False


def main():
    if not wait_for_services():
        sys.exit(1)

    # Ensure screenshots dir exists and clear old PNGs
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    old_pngs = glob.glob(str(SCREENSHOTS_DIR / "*.png"))
    for f in old_pngs:
        try:
            os.remove(f)
        except OSError:
            pass
    print(f"[*] Cleared previous screenshots. Target directory: {SCREENSHOTS_DIR}")

    with sync_playwright() as p:
        print("[*] Launching Chromium browser (viewport 1600x1000, retina scale x2)...")
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1600, "height": 1000},
            device_scale_factor=2
        )
        page = context.new_page()

        print(f"[*] Navigating to {FRONTEND_URL}...")
        page.goto(FRONTEND_URL, wait_until="networkidle")

        # Wait for critical elements to be present and rendered
        page.wait_for_selector("#header-kpis-section", timeout=15000)
        page.wait_for_selector("#threat-signals-section", timeout=15000)
        page.wait_for_selector("#primary-charts-grid", timeout=15000)
        page.wait_for_selector("#chart-protocol-donut svg", timeout=15000)
        page.wait_for_selector("#chart-host-flow-sankey", timeout=15000)
        page.wait_for_selector("#chart-conversation-heatmap", timeout=15000)
        page.wait_for_selector("#packet-explorer-section table tbody tr", timeout=15000)

        # Allow animations to settle
        print("[*] Allowing animations and layouts to settle (2000ms)...")
        time.sleep(2.0)

        # 1. 01_full_dashboard.png - full-page screenshot of entire dashboard
        print("[1/14] Capturing 01_full_dashboard.png...")
        page.screenshot(
            path=str(SCREENSHOTS_DIR / "01_full_dashboard.png"),
            full_page=True
        )

        # 2. 02_header_kpis.png - element screenshot of top bar + KPI cards
        print("[2/14] Capturing 02_header_kpis.png...")
        header_kpi = page.locator("#header-kpis-section")
        header_kpi.scroll_into_view_if_needed()
        time.sleep(0.3)
        header_kpi.screenshot(path=str(SCREENSHOTS_DIR / "02_header_kpis.png"))

        # Expand ALL threat alert cards before capturing the threat section
        print("[*] Programmatically expanding all threat alert cards...")
        threat_section = page.locator("#threat-signals-section")
        threat_section.scroll_into_view_if_needed()
        time.sleep(0.3)
        
        expand_buttons = page.locator('[data-testid="inspect-evidence-btn"]').all()
        for i, btn in enumerate(expand_buttons):
            btn.scroll_into_view_if_needed()
            btn.click()
            time.sleep(0.2)
        
        # Wait a moment for expanded evidence tables to fully layout
        time.sleep(0.8)

        # 3. 03_threat_panel.png - full Threat Signals section with all cards expanded
        print("[3/14] Capturing 03_threat_panel.png (all alerts expanded)...")
        threat_section.screenshot(path=str(SCREENSHOTS_DIR / "03_threat_panel.png"))

        # 4. 04_charts_grid.png - element screenshot of 2-column chart grid
        print("[4/14] Capturing 04_charts_grid.png...")
        charts_grid = page.locator("#primary-charts-grid")
        charts_grid.scroll_into_view_if_needed()
        time.sleep(0.5)
        charts_grid.screenshot(path=str(SCREENSHOTS_DIR / "04_charts_grid.png"))

        # Individual chart element screenshots
        charts_to_capture = [
            ("05_protocol_donut.png", "#chart-protocol-donut", "[5/14]"),
            ("06_top_talkers.png", "#chart-top-talkers", "[6/14]"),
            ("07_traffic_timeline.png", "#chart-traffic-timeline", "[7/14]"),
            ("08_packet_sizes.png", "#chart-packet-sizes", "[8/14]"),
            ("09_dst_ports.png", "#chart-dst-ports", "[9/14]"),
            ("10_port_scan_scatter.png", "#chart-port-scan-scatter", "[10/14]"),
            ("11_host_flow_sankey.png", "#chart-host-flow-sankey", "[11/14]"),
            ("12_conversation_heatmap.png", "#chart-conversation-heatmap", "[12/14]"),
        ]

        for filename, selector, step_label in charts_to_capture:
            print(f"{step_label} Capturing {filename}...")
            loc = page.locator(selector)
            loc.scroll_into_view_if_needed()
            time.sleep(0.3)
            loc.screenshot(path=str(SCREENSHOTS_DIR / filename))

        # 13. 13_packet_explorer.png - packet explorer table with filter controls
        print("[13/14] Capturing 13_packet_explorer.png...")
        explorer = page.locator("#packet-explorer-section")
        explorer.scroll_into_view_if_needed()
        time.sleep(0.5)
        explorer.screenshot(path=str(SCREENSHOTS_DIR / "13_packet_explorer.png"))

        # 14. 14_parser_badge.png - tight crop of the parser-engine badge
        print("[14/14] Capturing 14_parser_badge.png...")
        badge = page.locator("#parser-engine-badge")
        badge.scroll_into_view_if_needed()
        time.sleep(0.3)
        badge.screenshot(path=str(SCREENSHOTS_DIR / "14_parser_badge.png"))

        browser.close()
        print("[+] All 14 screenshots captured successfully.")


if __name__ == "__main__":
    main()
