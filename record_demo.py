#!/usr/bin/env python3
"""
record_demo.py
--------------
Records a ~16-18 second interactive demo of the WireScope React frontend with
Playwright and encodes it into a smooth, jitter-free docs/demo.gif (plus a
docs/demo.mp4 fallback).

Smoothness notes (why this looks fluid and not choppy):
  * The GIF is encoded at 20 fps (not 12) so scrolling and chart animations
    read as continuous motion.
  * A single STABLE global palette is generated (palettegen stats_mode=full),
    so colors don't shift frame-to-frame — that frame-to-frame palette drift is
    the main cause of the "shimmer/jitter" you see in cheap GIFs.
  * paletteuse uses sierra2_4a error-diffusion dithering (smooth on gradients)
    instead of ordered bayer dithering (which adds a static crosshatch that
    crawls between frames). diff_mode is left off so no blocky partial updates.
  * Every interaction is followed by a settle wait so Recharts' ~380ms entrance
    animations finish BEFORE the next action — nothing is captured mid-animation.

Run it with both local servers up (./run_all.sh), so the parser badge shows the
real PyShark/tshark engine rather than the Scapy fallback:

    source .venv/bin/activate
    python record_demo.py

Optional: set DEMO_URL to point at a different origin (defaults to local dev).
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

DEMO_URL = os.environ.get("DEMO_URL", "http://localhost:5173")

# --- Encoding knobs (smoothness vs. file size) --------------------------------
GIF_FPS = 18          # 18 is still fluid; trims size vs 20
GIF_WIDTH = 760       # px; crisp on a README while keeping the GIF ~7-9 MB
GIF_SIZE_WARN_MB = 12 # above this, lean on the mp4 fallback
# Stable global palette + error-diffusion dithering = no inter-frame shimmer.
PALETTE_VF = f"fps={GIF_FPS},scale={GIF_WIDTH}:-1:flags=lanczos,palettegen=max_colors=200:stats_mode=full"
GIF_LAVFI = (
    f"fps={GIF_FPS},scale={GIF_WIDTH}:-1:flags=lanczos [x]; "
    f"[x][1:v] paletteuse=dither=sierra2_4a"
)


def _settle(page, ms):
    """Wait for the network to go quiet AND a fixed beat, so animations finish."""
    try:
        page.wait_for_load_state("networkidle", timeout=4000)
    except Exception:
        pass
    page.wait_for_timeout(ms)


def record_interactive_demo():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    if TEMP_VIDEO_DIR.exists():
        shutil.rmtree(TEMP_VIDEO_DIR)
    TEMP_VIDEO_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[*] Recording interactive demo from {DEMO_URL} ...")
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            # Force a steady 30fps capture so motion is evenly sampled.
            args=["--force-device-scale-factor=1"],
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            device_scale_factor=1,
            record_video_dir=str(TEMP_VIDEO_DIR),
            record_video_size={"width": 1280, "height": 800},
            reduced_motion="no-preference",  # keep the app's entrance animations
        )
        page = context.new_page()

        # 1. Initial load — Full Attack Chain is the default scenario.
        print("  [>] Loading dashboard ...")
        page.goto(DEMO_URL, wait_until="networkidle")
        page.wait_for_selector("#scenario-btn-full_attack:not([disabled])", timeout=30000)
        _settle(page, 1900)  # let KPIs, threat panel and charts finish animating in

        # 2. Expand the Port Scan evidence table (detail-on-demand).
        print("  [>] Expanding Port Scan evidence ...")
        inspect_btn = page.locator("button:has-text('Inspect Evidence')").first
        if inspect_btn.count() and inspect_btn.is_visible():
            inspect_btn.scroll_into_view_if_needed()
            page.wait_for_timeout(500)
            inspect_btn.click()
            _settle(page, 1700)

        # 3. Switch to the 'Port Scan' scenario — whole dashboard re-renders.
        print("  [>] Switching to 'Port Scan' ...")
        page.locator("#scenario-btn-port_scan").click()
        page.wait_for_selector("#scenario-btn-port_scan:not([disabled])", timeout=20000)
        _settle(page, 2000)

        # 4. Scroll to the Packet Explorer and filter by the scanner's IP.
        #    Scroll in two gentle steps so the smooth-scroll reads fluidly at 20fps.
        print("  [>] Scrolling to Packet Explorer and filtering ...")
        page.evaluate("window.scrollBy({ top: 460, behavior: 'smooth' })")
        page.wait_for_timeout(700)
        page.evaluate("window.scrollBy({ top: 460, behavior: 'smooth' })")
        page.wait_for_timeout(1000)

        search_input = page.locator("input[placeholder*='Search IP address']").first
        if search_input.count() and search_input.is_visible():
            search_input.click()
            # Type the IP character-by-character so the live filter animates.
            search_input.type("192.168.1.99", delay=70)
            _settle(page, 1900)

        # 5. Scroll back to top and switch to 'Benign Baseline' (0 alerts).
        print("  [>] Back to top, switching to 'Benign Baseline' ...")
        page.evaluate("window.scrollTo({ top: 0, behavior: 'smooth' })")
        page.wait_for_timeout(1100)
        page.locator("#scenario-btn-normal").click()
        page.wait_for_selector("#scenario-btn-normal:not([disabled])", timeout=20000)
        _settle(page, 2200)  # lingers on the green "no threats" state

        # 6. Return to 'Full Attack Chain' to close the loop.
        print("  [>] Switching back to 'Full Attack Chain' ...")
        page.locator("#scenario-btn-full_attack").click()
        page.wait_for_selector("#scenario-btn-full_attack:not([disabled])", timeout=20000)
        _settle(page, 1900)

        context.close()
        browser.close()

    video_files = list(TEMP_VIDEO_DIR.glob("*.webm"))
    if not video_files:
        raise RuntimeError("No video file was produced in docs/temp_video/.")
    src_video = video_files[0]
    print(f"[+] Raw capture: {src_video.name} ({src_video.stat().st_size / 1024:.1f} KB)")

    mp4_path = DOCS_DIR / "demo.mp4"
    gif_path = DOCS_DIR / "demo.gif"
    palette_path = DOCS_DIR / "palette.png"

    ffmpeg_bin = shutil.which("ffmpeg") or "/opt/homebrew/bin/ffmpeg"
    if not os.path.exists(ffmpeg_bin):
        raise RuntimeError(
            f"ffmpeg not found (looked for {ffmpeg_bin}). Install it: brew install ffmpeg"
        )

    # --- MP4 (H.264): inherently smooth; the downloadable fallback ------------
    print("[*] Encoding MP4 (H.264) ...")
    subprocess.run(
        [
            ffmpeg_bin, "-y", "-i", str(src_video),
            "-c:v", "libx264", "-preset", "slow", "-crf", "20",
            "-pix_fmt", "yuv420p",
            # Even dimensions are required by yuv420p.
            "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2",
            str(mp4_path),
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    mp4_mb = mp4_path.stat().st_size / (1024 * 1024)
    print(f"[+] {mp4_path.name}  ({mp4_mb:.2f} MB)")

    # --- GIF: stable palette + sierra2_4a dithering = smooth, no shimmer ------
    print("[*] Generating stable global palette ...")
    subprocess.run(
        [ffmpeg_bin, "-y", "-i", str(src_video), "-vf", PALETTE_VF, str(palette_path)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    print(f"[*] Encoding GIF at {GIF_FPS} fps ...")
    subprocess.run(
        [
            ffmpeg_bin, "-y",
            "-i", str(src_video), "-i", str(palette_path),
            "-lavfi", GIF_LAVFI,
            str(gif_path),
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    if palette_path.exists():
        palette_path.unlink()
    shutil.rmtree(TEMP_VIDEO_DIR, ignore_errors=True)

    gif_mb = gif_path.stat().st_size / (1024 * 1024)
    print("\n" + "=" * 60)
    print(f"[+] Demo GIF: {gif_path}  ({gif_mb:.2f} MB)")
    if gif_mb > GIF_SIZE_WARN_MB:
        print(
            f"    NOTE: GIF is above {GIF_SIZE_WARN_MB} MB. It still renders on GitHub "
            f"(hard limit 25 MB), but you can shrink it by lowering GIF_WIDTH or GIF_FPS.\n"
            f"    The mp4 fallback is already smooth at {mp4_mb:.2f} MB."
        )
    print(f"[+] Fallback MP4: {mp4_path}  ({mp4_mb:.2f} MB)")
    print("=" * 60)

    return gif_path, gif_mb


if __name__ == "__main__":
    record_interactive_demo()
