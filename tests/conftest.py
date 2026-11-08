import os

import pytest

# Modal's SDK reads its profile file when imported. Tests never load the user's profile.
os.environ["MODAL_CONFIG_PATH"] = os.path.join(os.path.dirname(__file__), "no-modal-profile.toml")


@pytest.fixture(autouse=True)
def free_disk_minimum(monkeypatch):
    """A test run's records are small, so the free-space floor applies only where a test sets it."""
    monkeypatch.setattr("nudi.run_state.FREE_DISK_MINIMUM", 0)
