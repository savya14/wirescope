#!/usr/bin/env python3
"""
record_demo.py
--------------
Automates capturing a high-quality ~15-18 second interactive demo session
of the PCAP Analyzer React frontend using Playwright, and encodes it into
both an optimized docs/demo.gif (<8MB) and docs/demo.mp4.

Workflow:
  1. Opens http://localhost:5173 (Full Attack Chain loaded by default).
  2. Highlights threat signals & expands Port Scan evidence table.
  3. Switches scenario to 'Port Scan' (alerts drop to 1).
  4. Scrolls to Packet Explorer & filters by IP '192.168.1.99'.
  5. Switches scenario to 'Benign Baseline' (0 alerts, CLEAR state).
  6. Switches back to 'Full Attack Chain'.
  7. Converts webm to docs/demo.mp4 and optimized docs/demo.gif via ffmpeg.
"""

import os
import shutil
import subprocess
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE_DIR = Path(__file__).resolve().parent
DOCS_DIR = BASE_DIR / "docs"
TEMP_VIDEO_DIR = DOCS_DIR / "temp_video"


def record_interactive_demo():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    if TEMP_VIDEO_DIR.exists():
        shutil.rmtree(TEMP_VIDEO_DIR)
    TEMP_VIDEO_DIR.mkdir(parents=True, exist_ok=True)

    print("[*] Launching headless browser to record interactive demo...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            device_scale_factor=1,
            record_video_dir=str(TEMP_VIDEO_DIR),
            record_video_size={"width": 1280, "height": 800},
        )
        page = context.new_page()

        # 1. Initial Load (Full Attack Chain)
        print("  [>] Navigating to dashboard (http://localhost:5173)...")
        page.goto("http://localhost:5173", wait_until="networkidle")
        page.wait_for_selector("#scenario-btn-full_attack:not([disabled])", timeout=20000)
        page.wait_for_timeout(1500)

        # 2. Inspect Threat Evidence (Expand Port Scan row)
        print("  [>] Expanding threat evidence on Port Scan alert...")
        inspect_btn = page.locator("button:has-text('Inspect Evidence')").first
        if inspect_btn.is_visible():
            inspect_btn.click()
            page.wait_for_timeout(1600)

        # 3. Switch Scenario to 'Port Scan'
        print("  [>] Switching to 'Port Scan' scenario...")
        page.locator("#scenario-btn-port_scan").click()
        page.wait_for_selector("#scenario-btn-port_scan:not([disabled])", timeout=15000)
        page.wait_for_timeout(1800)

        # 4. Scroll to Packet Explorer and filter
        print("  [>] Scrolling to Packet Explorer and filtering...")
        page.evaluate("window.scrollBy({ top: 880, behavior: 'smooth' })")
        page.wait_for_timeout(1200)

        search_input = page.locator("input[placeholder*='Search IP address']").first
        if search_input.is_visible():
            search_input.click()
            search_input.fill("192.168.1.99")
            page.wait_for_timeout(1800)

        # 5. Scroll back up and switch to 'Benign Baseline'
        print("  [>] Scrolling to top and switching to 'Benign Baseline'...")
        page.evaluate("window.scrollTo({ top: 0, behavior: 'smooth' })")
        page.wait_for_timeout(1000)

        page.locator("#scenario-btn-normal").click()
        page.wait_for_selector("#scenario-btn-normal:not([disabled])", timeout=15000)
        page.wait_for_timeout(2200)

        # 6. Switch back to 'Full Attack Chain'
        print("  [>] Switching back to 'Full Attack Chain'...")
        page.locator("#scenario-btn-full_attack").click()
        page.wait_for_selector("#scenario-btn-full_attack:not([disabled])", timeout=15000)
        page.wait_for_timeout(1800)

        # Close context and browser to finalize video file
        context.close()
        browser.close()

    # Find the recorded video file
    video_files = list(TEMP_VIDEO_DIR.glob("*.webm"))
    if not video_files:
        raise RuntimeError("No video file found in temp_video_dir!")

    src_video = video_files[0]
    print(f"[+] Raw video recorded: {src_video} ({src_video.stat().st_size / 1024:.1f} KB)")

    # Output paths
    mp4_path = DOCS_DIR / "demo.mp4"
    gif_path = DOCS_DIR / "demo.gif"
    palette_path = DOCS_DIR / "palette.png"

    ffmpeg_bin = shutil.which("ffmpeg") or "/opt/homebrew/bin/ffmpeg"
    if not os.path.exists(ffmpeg_bin):
        raise RuntimeError(f"ffmpeg binary not found at {ffmpeg_bin}")

    # Convert to MP4
    print("[*] Encoding MP4 (H.264)...")
    cmd_mp4 = [
        ffmpeg_bin, "-y",
        "-i", str(src_video),
        "-c:v", "libx264",
        "-preset", "slow",
        "-crf", "22",
        "-pix_fmt", "yuv420p",
        str(mp4_path),
    ]
    subprocess.run(cmd_mp4, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    mp4_size_mb = mp4_path.stat().st_size / (1024 * 1024)
    print(f"[+] Created {mp4_path} ({mp4_size_mb:.2f} MB)")

    # Convert to High-Quality Optimized GIF using 2-pass palettegen
    # Using 12 fps, 960px width for ideal compromise between crispness and <8MB size
    print("[*] Generating optimized color palette for GIF...")
    cmd_palette = [
        ffmpeg_bin, "-y",
        "-i", str(src_video),
        "-vf", "fps=12,scale=960:-1:flags=lanczos,palettegen=stats_mode=diff",
        str(palette_path),
    ]
    subprocess.run(cmd_palette, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("[*] Encoding GIF with paletteuse...")
    cmd_gif = [
        ffmpeg_bin, "-y",
        "-i", str(src_video),
        "-i", str(palette_path),
        "-lavfi", "fps=12,scale=960:-1:flags=lanczos [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle",
        str(gif_path),
    ]
    subprocess.run(cmd_gif, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if palette_path.exists():
        palette_path.unlink()
    shutil.rmtree(TEMP_VIDEO_DIR, ignore_errors=True)

    gif_size_mb = gif_path.stat().st_size / (1024 * 1024)
    print(f"\n============================================================")
    print(f"[+] SUCCESS! Demo GIF created: {gif_path}")
    print(f"    File size: {gif_size_mb:.2f} MB (< 8 MB target: {'PASS' if gif_size_mb < 8.0 else 'EXCEEDED'})")
    print(f"[+] Fallback MP4 created: {mp4_path} ({mp4_size_mb:.2f} MB)")
    print(f"============================================================")

    return gif_path, gif_size_mb


if __name__ == "__main__":
    record_interactive_demo()
