"""Configuration loader for IRIS."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# Mapping of environment variable names to config api_keys entries.
_ENV_KEY_MAP: dict[str, str] = {
    "VIRUSTOTAL_API_KEY": "virustotal",
    "GOOGLE_SAFEBROWSING_API_KEY": "google_safebrowsing",
    "PHISHTANK_API_KEY": "phishtank",
    "URLHAUS_API_KEY": "urlhaus",
    "ABUSEIPDB_API_KEY": "abuseipdb",
}


# Search for config in common locations
_POSSIBLE_CONFIG_PATHS = [
    Path("/app/config/default.yaml"),  # Docker container path
    Path(__file__).resolve().parent.parent.parent / "config" / "default.yaml",  # Source repo path
    Path.cwd() / "config" / "default.yaml",  # Current working directory
]

DEFAULT_CONFIG_PATH = next(
    (p for p in _POSSIBLE_CONFIG_PATHS if p.exists()),
    _POSSIBLE_CONFIG_PATHS[0],
)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override dict into base dict."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Load configuration from YAML files.

    Loads the default config, then merges with a local override file
    (config/local.yaml) or a user-specified config path.

    Args:
        config_path: Optional path to a config YAML file. If provided,
            it is merged on top of the default config.

    Returns:
        Merged configuration dictionary.
    """
    with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # Try loading local.yaml as an override
    local_path = DEFAULT_CONFIG_PATH.parent / "local.yaml"
    if local_path.exists():
        with open(local_path, "r", encoding="utf-8") as f:
            local_config = yaml.safe_load(f) or {}
        config = _deep_merge(config, local_config)

    # Apply user-specified config on top
    if config_path is not None:
        user_path = Path(config_path)
        if user_path.exists():
            with open(user_path, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f) or {}
            config = _deep_merge(config, user_config)

    # Overlay API keys from environment variables (highest priority).
    # This allows Docker users to pass keys via `docker compose` environment
    # section without needing a local.yaml file.
    api_keys = config.setdefault("api_keys", {})
    for env_var, key_name in _ENV_KEY_MAP.items():
        value = os.getenv(env_var, "")
        if value:
            api_keys[key_name] = value

    return config


def get_api_key(config: dict[str, Any], feed_name: str) -> str:
    """Retrieve an API key from config, returning empty string if missing.

    Args:
        config: The loaded configuration dictionary.
        feed_name: Name of the feed (e.g., 'virustotal').

    Returns:
        The API key string, or empty string if not configured.
    """
    return config.get("api_keys", {}).get(feed_name, "")
