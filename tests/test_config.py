"""Runtime configuration: the file names hosts and URLs, never secrets.

The one credential that ever came from outside the vault - the Jellyfin
minting key - is retired: a live Jellyfin showed any API key can mint its own
successor, so no second key exists to name. These tests go through the loader,
because a config rule can quietly stop being enforced there.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from credarr.config import ConfigError, load_config


def _config(tmp_path: Path, extra: str = "", host_extra: str = "") -> Path:
    path = tmp_path / "credarr.yaml"
    path.write_text(
        "version: 1\n"
        "default_host: media\n"
        "manifest: m.yml\n"
        + extra
        + "hosts:\n"
        "  media:\n" + host_extra
    )
    return path


def test_a_secret_value_in_the_config_is_refused(tmp_path):
    """The file's one rule: it names where secrets live, it never holds one."""
    path = _config(tmp_path, host_extra="    jellyfin_auth_key: a-real-key-value\n")

    with pytest.raises(ConfigError, match="jellyfin_auth_key"):
        load_config(path)


def test_the_retired_minting_key_field_is_refused(tmp_path):
    """An old config naming the second key stops loudly, not silently.

    The field was real and load-bearing once, so a config carrying it is
    either stale or a guess - and ignoring either would leave an operator
    managing a secret they believe credarr still reads.
    """
    path = _config(
        tmp_path, host_extra="    jellyfin_auth_key_env: CREDARR_TEST_JELLYFIN_MINT_KEY\n"
    )

    with pytest.raises(ConfigError, match="jellyfin_auth_key_env"):
        load_config(path)


@pytest.mark.parametrize("field", ["transport", "ssh", "sudo"])
def test_retired_transport_fields_are_refused_on_a_host(tmp_path, field):
    path = _config(tmp_path, host_extra=f"    {field}: local\n")

    with pytest.raises(ConfigError, match=field):
        load_config(path)


@pytest.mark.parametrize("field", ["transport", "ssh", "sudo"])
def test_retired_transport_fields_are_refused_at_the_top_level(tmp_path, field):
    path = _config(tmp_path, extra=f"{field}: local\n")

    with pytest.raises(ConfigError, match=field):
        load_config(path)


@pytest.mark.parametrize("setting", ["restart_url", "restart_containers"])
def test_a_retired_restart_setting_is_refused_at_the_top_level(tmp_path, setting):
    path = _config(tmp_path, extra=f"{setting}: http://proxy:2375\n")

    with pytest.raises(ConfigError, match=setting):
        load_config(path)


@pytest.mark.parametrize("setting", ["restart_url", "restart_timeout"])
def test_a_retired_restart_setting_is_refused_on_a_host(tmp_path, setting):
    path = _config(tmp_path, host_extra=f"    {setting}: 30\n")

    with pytest.raises(ConfigError, match=setting):
        load_config(path)


def test_an_empty_restart_url_is_still_refused(tmp_path):
    """Presence is the stale configuration, not a non-empty value."""
    path = _config(tmp_path, extra="restart_url: ''\n")

    with pytest.raises(ConfigError, match="restart_url"):
        load_config(path)


def test_a_default_host_typo_is_an_unknown_key(tmp_path):
    """The fallback to the first host is for an omitted key, not a misspelled
    one that would silently target another stack."""
    path = _config(tmp_path, extra="default_hots: media\n")

    with pytest.raises(ConfigError, match="default_hots"):
        load_config(path)


def test_unknown_keys_are_refused_at_each_level(tmp_path):
    path = _config(tmp_path, extra="urlls: {}\n")
    with pytest.raises(ConfigError, match="urlls"):
        load_config(path)

    path = _config(tmp_path, host_extra="    urlls: {}\n")
    with pytest.raises(ConfigError, match="urlls"):
        load_config(path)

    path = tmp_path / "fingerprint.yaml"
    path.write_text(
        "version: 1\ndefault_host: media\nmanifest: m.yml\n"
        "fingerprint:\n  pinned_slat: abc\n"
        "hosts:\n  media: {}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="pinned_slat"):
        load_config(path)


def test_a_duplicate_config_key_is_refused(tmp_path):
    path = tmp_path / "credarr.yaml"
    path.write_text(
        "version: 1\ndefault_host: media\nmanifest: m.yml\n"
        "hosts:\n  media: {}\nhosts:\n  other: {}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="duplicate key"):
        load_config(path)


@pytest.mark.parametrize("version", ["true", "1.0"])
def test_the_config_version_must_be_the_integer_one(tmp_path, version):
    path = tmp_path / "credarr.yaml"
    path.write_text(
        f"version: {version}\ndefault_host: media\nmanifest: m.yml\n"
        "hosts:\n  media: {}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="not supported"):
        load_config(path)


def test_vault_password_file_stays_a_supported_config_key(tmp_path):
    path = _config(
        tmp_path,
        extra="vault_password_file: .vault_pass\n",
        host_extra="    urls: {}\n",
    )
    assert load_config(path).default_host == "media"


def test_a_non_string_default_host_is_refused(tmp_path):
    path = _config(tmp_path, extra="")
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "default_host: media", "default_host: [media]"
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="default_host"):
        load_config(path)


def test_a_non_utf8_config_is_a_config_error(tmp_path):
    path = tmp_path / "credarr.yaml"
    path.write_bytes(b"version: 1\n# \xff\nhosts: {}\n")
    with pytest.raises(ConfigError, match="cannot read config"):
        load_config(path)
