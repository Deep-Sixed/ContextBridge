"""Phase 3 media capability inventory.

This module never opens a camera, records audio, plays sound, or accesses
media streams. Presence is indicative only, not proof that a device is usable.
"""
from __future__ import annotations

import os
from pathlib import Path


def media_inventory(*, authorized: bool = False) -> dict:
    """Report bounded local device counts; deny all inspection by default."""
    if authorized is not True:
        raise PermissionError("media discovery is disabled")
    if os.name == "nt":
        # Windows Multimedia wave counts are device hints, not active streams.
        import ctypes
        winmm = ctypes.WinDLL("winmm")
        cameras = None  # Video devices require a separate Media Foundation adapter.
        microphones = int(winmm.waveInGetNumDevs())
        speakers = int(winmm.waveOutGetNumDevs())
    else:
        # Device nodes can exist without a usable video session or camera.
        cameras = sum(1 for p in Path("/dev").glob("video[0-9]*") if p.name[5:].isdigit()) if Path("/dev").exists() else 0
        microphones = None  # No reliable stdlib-only ALSA/PulseAudio/PipeWire count.
        speakers = None
    return {
        "camera_device_hints": cameras,
        "microphone_device_hints": microphones,
        "speaker_device_hints": speakers,
        "stream_access": False,
        "recording_active": False,
        "limitations": "Counts are hints only; no capture, playback, or device opening.",
    }
