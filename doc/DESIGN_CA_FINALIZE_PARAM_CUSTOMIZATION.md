# CA-Specific Finalize Payload Customization

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- Stateless client rationale: [DESIGN_STATEFUL_CLIENT_ANALYSIS.md](DESIGN_STATEFUL_CLIENT_ANALYSIS.md)
- [`acme/client.py`](../acme/client.py) — client implementation
- [`main.py`](../main.py) — CLI override precedent (`--ca-provider`, `--acme-directory-url`)
- taskfw `task:1490d568` — scoping/grooming record for this design

**Date:** 2026-08-19
**Status:** Implemented — `acme/client.py`, `config.py`, `main.py`, `tests/test_finalize_params.py`
**Category:** Extension point

---

## Problem

`AcmeClient.finalize_order()` (`acme/client.py:301-316`) builds a fixed payload
for every CA:

```python
resp = self._post_signed({"csr": csr_b64}, account_key, nonce, finalize_url, account_url)
```

RFC 8555 §7.4 defines `csr` as the only required field in a finalize request,
but some CAs accept (or require) additional vendor-specific fields in that
same JSON body. There is currently no way to add one without editing
`finalize_order()` itself — which would mean a per-CA `if` branch inside the
one function every CA's finalize call goes through, in direct tension with
this project's determinism and explicit-state principles.

This document scopes an extension point for CA-specific finalize
parameters, with two sources: a CA-specific **default** (code) and an
operator-specified **override** (CLI), both bounded by a fail-closed
whitelist.

---

## Existing mechanism this follows

`AcmeClient`'s docstring already states the intended extension pattern:

> "Base RFC 8555 client. Subclass to add CA-specific behaviour (EAB, preset
> URLs)." — `acme/client.py:44`

EAB credentials and preset directory URLs are both threaded through today via
subclass `__init__` overrides (`DigiCertAcmeClient`, `LetsEncryptAcmeClient`,
etc.), constructed by `_client_registry()` (`acme/client.py:568-618`) and
returned from `make_client()` (`acme/client.py:621-628`). CA identity at the
`finalize_order()` call site (`agent/nodes/finalizer.py`) is not a lookup key
— it is the concrete subclass of the already-instantiated `client` object.
`finalize_order()`'s own signature carries no CA identifier.

This design reuses that pattern rather than introducing a parallel one (e.g.
a standalone `CaConfig` file keyed by provider string), to avoid two
competing ways of expressing "CA-specific behaviour" in the same module.

CLI overrides follow the existing precedent in `main.py`:
`--ca-provider` / `--acme-directory-url` are parsed as `argparse` flags
(`main.py:461-470`) and applied via `apply_runtime_settings_overrides()`
(`main.py:366-386`), which builds a new `config.AcmeConfig` via
`build_settings_from_override()` (`main.py:339-363`) and swaps the
`config.settings` singleton for the remainder of the process. The new flag
below follows the same shape.

---

## Design

### 1. Subclass hook — CA-specific defaults

```python
class AcmeClient:
    def _extra_finalize_params(self) -> dict[str, str]:
        """CA-specific fields to merge into the finalize payload. Override in subclasses."""
        return {}
```

Any CA subclass that needs default extra fields overrides this method. The
base implementation returns `{}`, so providers needing no customization
(Let's Encrypt, `custom`) require no changes.

### 2. Static per-CA whitelist

```python
# Colocated with _client_registry in acme/client.py
_FINALIZE_PARAM_WHITELIST: dict[str, frozenset[str]] = {
    "digicert": frozenset(),
    "letsencrypt": frozenset(),
    "letsencrypt_staging": frozenset(),
    "zerossl": frozenset(),
    "sectigo": frozenset(),
    "custom": frozenset(),
}
```

This whitelist governs what an *operator* may set via the CLI for a given
CA — it is independent of, and disjoint from, whatever keys a subclass's
`_extra_finalize_params()` sets by default. A CA absent from this dict is
treated as an empty whitelist (fail closed): adding a new CA to
`_client_registry` without a matching whitelist entry never silently opens
the door to arbitrary keys.

`"csr"` must never appear in any CA's whitelist — enforced by an assertion
at module load (or a unit test), since it is the one field the base payload
always sets and must never be overridden.

### 3. CLI flag — operator override

```python
parser.add_argument(
    "--optional-keys",
    nargs="+",
    metavar="KEY:VALUE",
    help="Extra CA-specific finalize params as key:value pairs, "
         "validated against the current CA's whitelist",
)
```

Parsed the same way `--ca-provider`/`--acme-directory-url` are: as a
process-wide override, applied once at startup. Each `key:value` token is
split on the first `:`; malformed tokens (no colon, empty key) are rejected
immediately — a parse error, not a runtime error.

### 4. Validation (fail closed, at parse/construction time)

For every `key:value` pair in `--optional-keys`:

1. Reject if `key` is not in the current CA's whitelist (`_FINALIZE_PARAM_WHITELIST[CA_PROVIDER]`).
2. Reject if `key == "csr"` (defense in depth — should already be unreachable per whitelist invariant above).
3. Reject if `key` is also a key returned by the client's `_extra_finalize_params()` — see disjointness, below.

All three are raised as `ValueError` during CLI/settings processing, before
any network call — consistent with the existing "fail fast at settings
construction" pattern used for EAB validation
(`AcmeConfig.validate_eab_credentials`, `config.py`).

### 5. Disjointness — no override semantics needed

CLI-supplied keys and subclass hook default keys are **intentionally
disjoint by design** — the CLI is not a mechanism for overriding a
CA-default value, only for adding operator-supplied ones the code doesn't
already set. There is therefore no precedence rule to design (no "CLI wins"
vs. "hook wins" question). If a whitelist entry and a hook's default keys
ever overlap, that is a configuration bug, not a legitimate case, and must
raise rather than silently resolve.

To keep this invariant from silently drifting (the whitelist and the
subclass's hook are edited independently over time), a CI test asserts, for
every CA in `_client_registry`, that its whitelist and its subclass's
`_extra_finalize_params()` output keys are disjoint. This runs in CI, not at
process startup — see "Resolved implementation items" below.

### 6. Merge point

```python
def finalize_order(self, finalize_url, csr_der, account_key, account_url, nonce):
    csr_b64 = base64.urlsafe_b64encode(csr_der).rstrip(b"=").decode()
    payload = {"csr": csr_b64}
    payload.update(self._extra_finalize_params())
    payload.update(self._cli_optional_keys())  # already validated at startup
    resp = self._post_signed(payload, account_key, nonce, finalize_url, account_url)
    return resp.json(), resp.headers.get("Replay-Nonce", "")
```

The merge happens inside the base class's `finalize_order()` itself.
Subclasses never override `finalize_order()` — only the hook method — so the
base RFC 8555 payload construction and signing flow stay authoritative for
every CA. `payload["csr"]` is set first and both subsequent `.update()`
calls are guaranteed (by the validation in §4 and the disjointness check in
§5) never to contain a `"csr"` key.

---

## Failure modes

| Condition | When detected | Behavior |
|---|---|---|
| `--optional-keys` token has no `:` | CLI parse | `ValueError`, process exits before any network call |
| Key not in current CA's whitelist | Settings construction | `ValueError`, fail closed |
| Key is `"csr"` in a whitelist definition | CI test (`tests/test_finalize_params.py`) | Test failure — should be unreachable, defense in depth |
| Whitelist key collides with hook default key | CI test (per registered CA) | Test failure before merge; never reaches a run |
| CA has no whitelist entry | Settings construction | Treated as empty set — any `--optional-keys` for that CA is rejected |

No condition here is discovered mid-run or after a signed request is sent —
all are structural/configuration checks that resolve before `finalize_order`
is ever reached, consistent with "fail toward doing nothing."

---

## Alternatives considered and rejected

**Standalone `CaConfig` file/class keyed by provider string.** Rejected —
duplicates the existing subclass-based extension point that EAB and
directory-URL customization already use; two mechanisms for the same kind
of behavior in the same module is a maintainability cost with no offsetting
benefit.

**Open-schema CLI input (arbitrary JSON blob).** Rejected — CLI input is
operator-controlled free-form data reaching a *signed* ACME request body.
Unlike EAB creds (a validated key_id/hmac pair) or `CA_PROVIDER` (an enum),
an arbitrary JSON blob has no schema to validate against. The whitelist
gives every accepted key a known owner (the CA it's whitelisted for) and a
known ceiling (only that CA's declared keys), instead of trusting arbitrary
operator input to a signed protocol message.

**CLI values override hook defaults per-key.** Rejected — not needed. The
two sources are disjoint by design; introducing override semantics would
add a precedence rule to reason about for a case that should never occur.

---

## Resolved implementation items

- **`_extra_finalize_params()` return type is `dict[str, str]`, confirmed.**
  No CA needs non-string values in the finalize payload; the CLI path
  (`--optional-keys key:value`) is string-only by construction anyway, so
  keeping the hook's type symmetric with it avoids a str/non-str split
  between the two merge sources.

- **The disjointness check lives in a separate CI test
  (`tests/test_finalize_params.py`), not inline in `_client_registry()`.**
  It runs once, at CI time, over every CA in `_client_registry` — asserting
  each CA's `_FINALIZE_PARAM_WHITELIST` entry and its subclass's
  `_extra_finalize_params()` output keys are disjoint, and that `"csr"` is
  never in a whitelist. This keeps `_client_registry()` itself free of
  assertion logic (it stays a plain constructor lookup, consistent with its
  current shape) while still catching drift before it ships, rather than at
  process startup on every run.

---

## Decision

Use the subclass-hook + static-whitelist design above. No new config file.
No CLI/hook precedence logic — collisions between the two sources are a bug,
not a feature. Implementation should proceed once the two open items above
are resolved.
