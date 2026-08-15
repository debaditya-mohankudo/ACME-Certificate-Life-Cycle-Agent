---
name: revoke-cert
description: >
  Hand-holds a non-technical user through revoking a TLS certificate via ACME:
  collects domain(s) and the plain-English reason ("the key leaked",
  "replaced by a new cert", "shutting the service down"), maps that to the
  RFC 5280 reason code, runs the revocation, and reports which domains
  succeeded/failed in plain language. WHEN: "revoke my certificate", "the
  private key leaked", "cancel this cert", "take down HTTPS for this domain".
  Project-scoped to this repo only.
---

# Revoke a TLS Certificate (guided)

This skill drives the agent's own CLI (`python main.py --revoke-cert ...`) —
it never bypasses the LangGraph revocation subgraph
(`agent/revocation_graph.py`) and never touches the ACME account key or
certificate private key directly. It exists to (a) translate a
non-technical reason into the correct RFC 5280 reason code, and (b) explain
the outcome per domain — revocation here is **best-effort**: unlike the
renewal graph, there is no `error_handler`/`retry_scheduler` in this
subgraph. A failed domain is logged to `failed_revocations` and the loop
moves on to the next domain unconditionally; it does not retry, skip-with-
backoff, or abort the whole run. Make sure the user understands that before
you run it.

## 1. Collect inputs (plain English, one question at a time)

1. **Domain name(s)** — "Which domain(s) do you want to revoke the
   certificate for?" (accept one or a space-separated list, e.g.
   `shop.example.com`). A local `cert.pem` must exist for each domain under
   `CERT_STORE_PATH` (default `./certs`, with a `<domain>/` subfolder per
   domain — see `storage/filesystem.py:read_cert_pem`) — if you're unsure,
   `ls` that path first and tell the user
   which of their requested domains don't have a stored cert (revocation
   will fail immediately for those, logged as "certificate file not found").

2. **Reason** — present as a plain-English choice, mapped to `--reason`
   (RFC 5280 codes; only these four are exposed by this CLI — see
   `main.py`'s `--reason` help text and `tui/screens/revoke.py:
   REASON_CODE_CHOICES`):
   - "No particular reason / just don't need it anymore" → `0` (unspecified)
   - "The private key leaked or was stolen" → `1` (keyCompromise) — flag
     this as urgent; also recommend the user rotate/replace the key itself,
     since revoking the cert alone doesn't invalidate a leaked key.
   - "It's being replaced by a new certificate" → `4` (superseded)
   - "We're shutting this service/domain down" → `5` (cessationOfOperation)
   Default to `0` only if the user has no preference — don't guess
   `1`/`4`/`5` on their behalf, since the CA and any monitoring downstream
   may treat `keyCompromise` differently (e.g. faster propagation, alerts).

## 2. Run the revocation

```bash
python main.py --revoke-cert <domain...> --reason <code>
```

This is a single subgraph run — sequential, one domain at a time, per this
repo's hard invariants (see root `CLAUDE.md`). Do not add `--schedule`, do
not invoke this concurrently with a renewal run (`--once`/`--schedule`)
against the same domains, since both touch the same ACME account key and
cert store.

Capture stdout — logging is JSONL to stdout (see `logger.py`), one JSON
object per line, so you can grep it for `"level": "ERROR"` or scan the final
summary line from `agent/nodes/reporter.py`'s
`_revocation_reporter_deterministic` (deterministic string formatting, not
an LLM call).

## 3. Report the outcome

Read `revoked_domains` and `failed_revocations` from the run's final
summary / log:

- **All requested domains in `revoked_domains`** — tell the user plainly:
  "The certificate for `<domain>` has been revoked. Browsers/clients that
  check revocation status (OCSP/CRL) will start rejecting it; others may
  still trust it until it expires naturally." If reason was `1`
  (keyCompromise), remind them to also rotate the private key if they
  haven't — revocation stops this cert being trusted, it doesn't undo a key
  leak.
- **Any domain in `failed_revocations`** — check `error_log` for that
  domain's line and translate it:
  - "certificate file not found" → no local `cert.pem` under
    `CERT_STORE_PATH` for that domain — nothing to revoke from this agent's
    side; ask if they meant a different domain or if the cert was issued
    elsewhere.
  - An ACME error from the CA (e.g. `alreadyRevoked`, `unauthorized`) →
    explain in plain terms and note that — unlike renewal — this subgraph
    will **not** retry it automatically; re-running step 2 for just that
    domain is the only way to try again.
- Since the subgraph doesn't abort on a per-domain failure, a mixed
  outcome (some revoked, some failed) in one run is normal — report each
  domain's result separately rather than treating the whole run as
  pass/fail.
