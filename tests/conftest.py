import os

# Modal's SDK reads its profile file when imported. Tests never load the user's profile.
os.environ["MODAL_CONFIG_PATH"] = os.path.join(os.path.dirname(__file__), "no-modal-profile.toml")
