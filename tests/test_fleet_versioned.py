"""Pure version-path planning: no live machine or service changes."""

import pytest

from contextbridge.fleet_versioned import version_paths

OLD = "a" * 40
NEW = "b" * 40


def test_linux_version_layout_preserves_previous_folder():
    p = version_paths(
        f"/home/jarvis/omnilink/version/{OLD}",
        "/home/jarvis/omnilink",
        NEW,
        windows=False,
    )
    assert p.target_checkout == f"/home/jarvis/omnilink/version/{NEW}"
    assert p.previous_checkout == f"/home/jarvis/omnilink/version/{OLD}"


def test_windows_version_layout_for_p70_migration():
    p = version_paths(
        "C:/ContextBridge",
        "C:/Omnilink",
        NEW,
        windows=True,
    )
    assert p.target_checkout == f"C:\\Omnilink\\version\\{NEW}"
    assert p.previous_checkout == "C:\\ContextBridge"


@pytest.mark.parametrize("ref", ["main", "accd8d7", "../evil", "A" * 40, "b" * 39])
def test_disallow_unsafe_version_directory_names(ref):
    with pytest.raises(ValueError, match="complete, lowercase"):
        version_paths("C:/ContextBridge", "C:/Omnilink", ref, windows=True)


def test_version_root_must_be_absolute():
    with pytest.raises(ValueError, match="absolute"):
        version_paths("/home/j/cb", "relative/root", NEW, windows=False)
