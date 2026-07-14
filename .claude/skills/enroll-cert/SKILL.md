---
name: enroll-cert
description: >
  Hand-holds a non-technical user through enrolling a new TLS certificate via ACME:
  collects domain + CA provider in plain English, runs the enrollment, and — when
  challenge validation fails — actively diagnoses why (DNS record checks, HTTP
  reachability checks) and explains the fix in plain language. WHEN: "get a cert
  for my domain", "enroll a certificate", "set up HTTPS/SSL for my site", "why did
  my certificate fail", "cert validation failed". Project-scoped to this repo only.
---

# Enroll a TLS Certificate (guided)

This skill drives the agent's own CLI (`python main.py --once ...`) — it never
bypasses the LangGraph state machine, never touches retry logic, and never runs
concurrent ACME operations. It exists to (a) collect the handful of inputs a
non-technical user needs to give in plain language, and (b) **diagnose *why* a
challenge failed** when the agent's own `error_handler` node reports a failure —
that diagnosis is the actual value of this skill; the intake step is just getting
there fast.

## 1. Collect inputs (plain English, one question at a time)

Ask only what's needed — don't dump ACME jargon on the user.

1. **Domain name(s)** — "What domain(s) do you want a certificate for?" (accept
   one or a space-separated list, e.g. `shop.example.com`).
2. **Certificate authority** — present as a plain-English choice, mapped to
   `--ca-provider`:
   - "Let's Encrypt (free, recommended for most sites)" → `letsencrypt`
   - "Let's Encrypt — test run first, no real cert issued" → `letsencrypt_staging`
   - "DigiCert" / "ZeroSSL" / "Sectigo" (paid/enterprise CAs) → `digicert` / `zerossl` / `sectigo`
   - "Something else (custom ACME server)" → `custom` (then also ask for the
     directory URL → `--acme-directory-url`)
   Recommend `letsencrypt_staging` first if the user seems unsure or this is
   their first attempt with a domain — it avoids burning Let's Encrypt's real-cert
   rate limits on a misconfiguration.
3. **EAB credentials** — only if provider is `digicert`/`zerossl`/`sectigo` and
   `ACME_EAB_KEY_ID`/`ACME_EAB_HMAC_KEY` aren't already set in `.env`. Explain:
   "This CA needs a key ID and HMAC key from your account dashboard with them —
   do you have those, or should I check `.env`?" Never ask the user to paste a
   private key into the conversation; only EAB key ID / HMAC key (these are
   binding credentials, not a certificate private key).
4. **How the CA can reach this server to verify domain ownership** — plain-English
   framing of `HTTP_CHALLENGE_MODE`:
   - "This server has a live website on port 80 I can borrow briefly" → `standalone`
   - "I have a web folder the CA's request should be dropped into" → `webroot`
     (then ask for the folder path → `WEBROOT_PATH`)
   - "I manage this domain's DNS instead" → `dns` (then ask which DNS provider:
     Cloudflare / Route53 / Google Cloud DNS → `DNS_PROVIDER`, and confirm the
     relevant credentials exist in `.env`)
   Only ask this if `HTTP_CHALLENGE_MODE`/`DNS_PROVIDER` aren't already configured
   for this domain in `.env`.

Check current `.env` values first (`Read` the file) before asking anything —
don't re-ask for settings that are already configured.

## 2. Run the enrollment

```bash
python main.py --once --domains <domain...> --ca-provider <provider> \
  [--acme-directory-url <url>]   # only if provider=custom
```

This is a single graph run — sequential, one domain at a time, per this repo's
hard invariants (see root `CLAUDE.md`). Do not add `--schedule`, do not run
multiple `--once` invocations concurrently, and do not attempt to parallelize
multi-domain runs.

Capture stdout — logging is JSONL to stdout (see `logger.py`), one JSON object
per line, so you can grep it for `"level": "ERROR"` or scan the final summary
line from `agent/nodes/reporter.py`.

If it succeeds: tell the user where the cert landed (`CERT_STORE_PATH`, default
`./certs/<domain>/`: `cert.pem`, `chain.pem`, `fullchain.pem`, `metadata.json`)
and stop here.

## 3. If challenge validation failed — diagnose, don't just relay

`error_handler` (agent/nodes/error_handler.py) already classifies the failure as
fatal (abort) or retryable (backoff/skip) based on substrings like
`unauthorized`, `accountdoesnotexist`, `badkey`, `externalaccountrequired` in the
ACME error. That classification alone isn't enough for a non-technical user —
run active diagnosis based on which challenge type was used, matched against the
failed domain(s) from the run's JSONL log / final state:

### HTTP-01 (`standalone` or `webroot` mode)

- Reachability: `curl -sS -o /dev/null -w '%{http_code}\n' http://<domain>/.well-known/acme-challenge/<token>`
  (token is in the run's log output / `agent/state.py` `AcmeOrder.challenge_tokens`).
  - Connection refused / timeout → port 80 isn't reachable from the public
    internet (firewall, router NAT, or `standalone` mode couldn't bind because
    something else already owns port 80 locally — check with
    `lsof -i :80` or equivalent).
  - 404 → in `webroot` mode, the file didn't land in `WEBROOT_PATH`, or the web
    server isn't serving `.well-known/acme-challenge/` from that root — check the
    web server's document-root config, not this agent.
  - 200 but wrong body → something else (a redirect rule, a catch-all app route)
    is intercepting the path before the CA's request; check for HTTPS-forcing
    redirects, since ACME's own request to the CA's validation servers is HTTP.
- `dig <domain> A` / `dig <domain> AAAA` to confirm the domain's DNS actually
  points at *this* server's public IP — a stale/wrong A record is the single
  most common non-technical-user cause of HTTP-01 failure, and looks identical
  to a firewall problem from the CA's side.

### DNS-01 (`dns` mode)

- `dig TXT _acme-challenge.<domain>` — confirm a TXT record exists with the
  expected value (`acme/dns_challenge.py:compute_dns_txt_value` —
  `base64url(SHA-256(key_authorization))`; the run's log will have the expected
  value if you need to diff it).
  - No record at all → provider API call failed silently, or wrong zone/API
    token — re-check `CLOUDFLARE_ZONE_ID`/`AWS_ROUTE53_HOSTED_ZONE_ID`/
    `GOOGLE_CLOUD_DNS_ZONE_NAME` actually match the domain's real zone.
  - Record exists but wrong value → likely a stale record from a prior failed
    run that wasn't cleaned up (query multiple TXT values — `_acme-challenge`
    can have several).
  - Record exists and correct, but the CA still failed → propagation delay;
    query a public resolver directly to bypass local DNS caching:
    `dig @8.8.8.8 TXT _acme-challenge.<domain>` and compare against your
    resolver's answer — if they differ, it's still propagating, and a retry in
    a few minutes (not a config change) is the right fix.

### Fatal errors (`unauthorized`, `accountdoesnotexist`, `badkey`, `externalaccountrequired`)

These abort immediately — no amount of DNS/HTTP retrying will fix them. Explain
in plain terms:
- `unauthorized` → the CA rejected proof of domain ownership; re-check whichever
  of the above (DNS/HTTP) diagnosis applies, since this is often the *terminal*
  error text for a challenge that failed validation.
- `accountdoesnotexist` / `badkey` → the local ACME account key
  (`ACCOUNT_KEY_PATH`) is stale or corrupted for this CA; the fix is deleting it
  and letting the agent register a fresh account on the next run — confirm with
  the user before deleting anything.
- `externalaccountrequired` → EAB credentials are missing/wrong for a CA that
  requires them (digicert/zerossl/sectigo) — go back to step 1.3.

## 4. Report and retry

Translate whatever you found into one sentence a non-technical user can act on
("Your domain's DNS is pointing to a different server than this one — update
the A record for shop.example.com to point here, then say 'try again'"), then
offer to re-run step 2 once they confirm they've made the fix. Don't loop
retries automatically beyond what `error_handler`/`retry_scheduler` already do —
this skill re-runs `--once` only on explicit user confirmation.
