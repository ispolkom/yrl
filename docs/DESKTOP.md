# YRL — remote desktop: design and why it is not implemented yet

## What exists instead (stage 3a, implemented and verified)

`yrl visual` is a mouse-enabled terminal file browser: folders, double click, bottom buttons, wheel scrolling, download/upload/create/rename/delete. It uses the same protected channels and the `files` permission, and acts as the account user. This supports opening folders and clicking with a mouse without graphics.

## What a real remote desktop means (stage 3b — NOT implemented)

Screen capture → encoding → transfer → display on the client, with mouse, keyboard, and clipboard flowing back.

### Design

- A separate **`desktop` permission**, plus **consent on the host**. No screen data is sent until the person at the machine clicks Allow, unless a persistent rule for that key has been enabled. The host always shows a “screen is being shared” indicator that cannot be hidden remotely. Clipboard and desktop file transfer are separate options, disabled by default. Sessions are not recorded.
- **Capture:** X11 (XShm + XDamage, changed regions only); Wayland only through the PipeWire portal with user consent; Windows through DXGI Desktop Duplication; macOS through ScreenCaptureKit. A `Capture` interface permits replaceable backends.
- **Encoding:** hardware H.264 where available, x264 fallback, and a basic MJPEG/delta-tile option for weak machines. Selection depends on both endpoints' capabilities.
- **Transport:** the resumable, reliable, ordered session layer preserves the stream across outages, but video needs freshness rather than completeness. `Link` therefore needs (1) **priorities**, so input and ACK overtake video instead of waiting behind megabytes of frames, and (2) **stale-data dropping**, so excessive unacknowledged video causes delta frames to be discarded and a keyframe requested. `DESK_OPEN/FRAME/INPUT/CLIPBOARD/CLOSE` use the reserved 60–69 range.
- **Client viewer:** a window, decoder, and input. It should be cross-platform on Linux/Windows/macOS, with a thin Android client. Choosing the windowing and decoder libraries is a separate decision.
- **Input safety:** events can be injected only while an approved session is active; rate limits apply; no shortcut may bypass the host indicator; the host lock screen cannot be bypassed.

### Why it is not implemented now

1. **There is no safe test environment.** This machine has no isolated X server (no Xvfb/Xephyr or xdotool); its only screen is the owner's live desktop (`:0`). Automated tests must not move the mouse or type on that desktop, and screenshots require explicit consent. The project rule is not to implement untestable behavior, so an isolated environment must come first.
2. **Offline libraries are unavailable.** `x11rb`, winit/SDL, and decoders are absent from the Cargo cache. `ffmpeg` exists as an external process, but making a parsed subprocess the heart of the product would create a weak boundary.
3. **The session layer needs independent work** on priorities and stale-data dropping; the chaos proxy already exists for testing it.

### Verification plan (once the environment exists)

Run Xvfb on a separate display number; use a synthetic application that draws known images; compare decoded client frames against references within codec tolerance; measure input-to-pixel latency; use the chaos proxy to disconnect during streaming (the first resumed frame must be a keyframe, while input is neither lost nor duplicated); fuzz decoders and frame parsers; verify the indicator and denial without consent; and load-test 30/60 fps at 4K.

### What is needed from the owner

Permission to install `xvfb` and `xdotool` (or another isolated X server), because these are system packages and are not installed automatically; alternatively, provide a spare machine or display for testing.
