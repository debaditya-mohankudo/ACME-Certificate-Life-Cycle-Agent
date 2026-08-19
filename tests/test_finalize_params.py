"""
CI-only invariants for the CA-specific finalize payload extension point.

See doc/DESIGN_CA_FINALIZE_PARAM_CUSTOMIZATION.md. These checks run once here,
not at process startup, so `_client_registry()` stays a plain constructor
lookup:

* every CA's `_FINALIZE_PARAM_WHITELIST` entry is disjoint from its
  subclass's `_extra_finalize_params()` default keys — the two sources are
  never meant to overlap, so a collision is a configuration bug;
* `"csr"` never appears in any CA's whitelist — it is the one field the base
  payload always sets and must never be overridden.
"""
from __future__ import annotations

import pytest

from acme.client import _FINALIZE_PARAM_WHITELIST, _client_registry


class _FakeSettings:
    ACME_CA_BUNDLE = ""
    ACME_INSECURE = False
    ACME_EAB_KEY_ID = "fake-key-id"
    ACME_EAB_HMAC_KEY = "fake-hmac-key"
    ACME_DIRECTORY_URL = "https://example.invalid/directory"
    OPTIONAL_FINALIZE_PARAMS: dict[str, str] = {}


@pytest.mark.parametrize("ca_provider", sorted(_FINALIZE_PARAM_WHITELIST))
def test_whitelist_disjoint_from_hook_defaults(ca_provider: str) -> None:
    client = _client_registry(ca_provider, _FakeSettings())
    default_keys = set(client._extra_finalize_params())
    whitelist = _FINALIZE_PARAM_WHITELIST[ca_provider]

    overlap = default_keys & whitelist
    assert not overlap, (
        f"CA_PROVIDER={ca_provider!r}: whitelist and _extra_finalize_params() "
        f"default keys must be disjoint, but both contain {overlap}"
    )


@pytest.mark.parametrize("ca_provider", sorted(_FINALIZE_PARAM_WHITELIST))
def test_csr_never_whitelisted(ca_provider: str) -> None:
    assert "csr" not in _FINALIZE_PARAM_WHITELIST[ca_provider], (
        f"CA_PROVIDER={ca_provider!r}: 'csr' must never be an operator-settable key"
    )
