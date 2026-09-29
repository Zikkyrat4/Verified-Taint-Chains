"""Low-level discovery and loading for VTC TOML configuration files."""

from __future__ import annotations

import os
from collections.abc import Mapping
from contextvars import ContextVar
from copy import deepcopy
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib  # type: ignore[no-redef]


CONFIG_FILE_NAME = "vtc.toml"
SUPPORTED_CONFIG_VERSION = 1

_cli_config_path: ContextVar[Path | None] = ContextVar("vtc_config_path", default=None)
_cli_profile: ContextVar[str | None] = ContextVar("vtc_config_profile", default=None)


def configure_cli_context(
    config_path: Path | None = None,
    profile: str | None = None,
) -> tuple[Any, Any]:
    """Set per-invocation config selectors for Click and nested commands."""
    path_token = _cli_config_path.set(config_path.expanduser().resolve() if config_path else None)
    profile_token = _cli_profile.set(profile)
    return path_token, profile_token


def reset_cli_context(tokens: tuple[Any, Any]) -> None:
    """Restore selectors after an in-process CLI invocation completes."""
    path_token, profile_token = tokens
    _cli_config_path.reset(path_token)
    _cli_profile.reset(profile_token)


def user_config_path() -> Path:
    """Return the platform-style per-user VTC configuration path."""
    configured_home = os.getenv("XDG_CONFIG_HOME")
    base = Path(configured_home).expanduser() if configured_home else Path.home() / ".config"
    return base / "vtc" / "config.toml"


def explicit_config_path() -> Path | None:
    """Return a CLI/environment-selected path, if one was supplied."""
    cli_path = _cli_config_path.get()
    if cli_path is not None:
        return cli_path
    configured = os.getenv("VTC_CONFIG")
    return Path(configured).expanduser().resolve() if configured else None


def discover_config_path(cwd: Path | None = None) -> Path | None:
    """Find the active file: explicit path, project file, then user file."""
    explicit = explicit_config_path()
    if explicit is not None:
        if not explicit.is_file():
            raise ValueError(f"Configuration file does not exist: {explicit}")
        return explicit

    project_path = (cwd or Path.cwd()) / CONFIG_FILE_NAME
    if project_path.is_file():
        return project_path.resolve()

    per_user = user_config_path()
    return per_user.resolve() if per_user.is_file() else None


def _deep_merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _deep_merge(dict(result[key]), value)
        else:
            result[key] = deepcopy(value)
    return result


def selected_profile(document: Mapping[str, Any]) -> str | None:
    """Resolve profile precedence: CLI, environment, then file default."""
    profile = _cli_profile.get() or os.getenv("VTC_PROFILE") or document.get("profile")
    if profile is None:
        return None
    if not isinstance(profile, str) or not profile.strip():
        raise ValueError("Configuration profile must be a non-empty string")
    return profile.strip()


def read_config_file(path: Path) -> dict[str, Any]:
    """Parse one TOML document with a contextual error message."""
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"Invalid TOML in {path}: {error}") from error
    except OSError as error:
        raise ValueError(f"Cannot read configuration file {path}: {error}") from error


def load_config_document(
    config_path: Path | None = None,
) -> tuple[dict[str, Any], Path | None, str | None]:
    """Load the active TOML file and merge its selected profile."""
    path = config_path.expanduser().resolve() if config_path else discover_config_path()
    if path is None:
        requested_profile = _cli_profile.get() or os.getenv("VTC_PROFILE") or None
        if requested_profile:
            raise ValueError(
                f"Configuration profile {requested_profile!r} was requested, "
                "but no vtc.toml was found"
            )
        return {}, None, None
    if not path.is_file():
        raise ValueError(f"Configuration file does not exist: {path}")

    document = read_config_file(path)

    version = document.get("version", SUPPORTED_CONFIG_VERSION)
    if version != SUPPORTED_CONFIG_VERSION:
        raise ValueError(
            f"Unsupported configuration version {version!r} in {path}; "
            f"expected {SUPPORTED_CONFIG_VERSION}"
        )

    profile = selected_profile(document)
    profiles = document.get("profiles", {})
    if not isinstance(profiles, Mapping):
        raise ValueError(f"'profiles' must be a TOML table in {path}")

    base = {
        key: value
        for key, value in document.items()
        if key not in {"version", "profile", "profiles"}
    }
    if profile:
        if profile not in profiles:
            available = ", ".join(sorted(profiles)) or "none"
            raise ValueError(
                f"Unknown configuration profile {profile!r} in {path}; " f"available: {available}"
            )
        profile_values = profiles[profile]
        if not isinstance(profile_values, Mapping):
            raise ValueError(f"Profile {profile!r} must be a TOML table in {path}")
        base = _deep_merge(base, profile_values)

    return base, path, profile


def file_setting(
    section: str,
    key: str,
    default: Any = None,
) -> Any:
    """Read one effective TOML value for non-pipeline subsystems."""
    document, _, _ = load_config_document()
    values = document.get(section, {})
    if not isinstance(values, Mapping):
        raise ValueError(f"Configuration section [{section}] must be a table")
    return values.get(key, default)


def environment_or_file_setting(
    env_name: str,
    section: str,
    key: str,
    default: Any = None,
    *,
    allow_empty: bool = False,
) -> Any:
    """Resolve a non-pipeline setting with ENV taking precedence over TOML."""
    if env_name in os.environ and (allow_empty or os.environ[env_name] != ""):
        return os.environ[env_name]
    return file_setting(section, key, default)
