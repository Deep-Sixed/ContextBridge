import pytest
from contextbridge.projects import RegistryError, load_registry


def test_project_mapping_is_metadata_not_capability(tmp_path):
    registry = tmp_path / "projects.yaml"
    registry.write_text("projects:\n  - name: ContextBridge\n    host: friday\n    path: /mnt/jarvis-data/projects/git/ContextBridge\n    github: Deep-Sixed/ContextBridge\n")
    value = load_registry(registry)
    assert value["count"] == 1
    assert value["authoritative"] is False
    assert value["projects"][0]["github"] == "Deep-Sixed/ContextBridge"


@pytest.mark.parametrize("payload", [
    "projects: {}",
    "projects:\n  - name: bad name\n    host: friday\n    path: /tmp\n    github: a/b",
    "projects:\n  - name: alpha\n    host: friday\n    path: /tmp\n    github: https://evil.example/x",
    "projects:\n  - name: alpha\n    host: friday\n    path: /tmp\n    github: a/b\n  - name: Alpha\n    host: friday\n    path: /tmp\n    github: a/b",
    "projects:\n  - name: alpha\n    host: friday\n    path: /tmp\n    github: a/b\n    extra: command",
])
def test_invalid_registry_denied(tmp_path, payload):
    path = tmp_path / "projects.yaml"
    path.write_text(payload)
    with pytest.raises(RegistryError):
        load_registry(path)
