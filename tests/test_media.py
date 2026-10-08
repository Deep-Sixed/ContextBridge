from unittest.mock import patch

import pytest

from contextbridge.computer.media import media_inventory


def test_media_inventory_denied_by_default():
    with pytest.raises(PermissionError):
        media_inventory()


def test_linux_media_inventory_never_starts_capture():
    with patch("contextbridge.computer.media.os.name", "posix"):
        report = media_inventory(authorized=True)
    assert report["stream_access"] is False
    assert report["recording_active"] is False
    assert report["microphone_device_hints"] is None
    assert report["speaker_device_hints"] is None
    assert report["camera_device_hints"] >= 0
