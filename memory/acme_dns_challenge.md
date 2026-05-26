---
name: acme-dns-challenge
description: DNS-01 challenge — TXT record computation, provider factory, propagation wait
metadata:
  type: project
  domain: acme
  priority: 20
  tags: dns, dns-01, challenge, cloudflare, route53, google-cloud-dns
---

DNS-01 is activated by `HTTP_CHALLENGE_MODE=dns` in `.env`. Implementation: `acme/dns_challenge.py`.

**TXT record value:** `base64url(SHA-256(key_authorization))` where `key_authorization = token + "." + jwk_thumbprint`.
**DNS name:** `_acme-challenge.{domain}`

**Provider factory:** `make_dns_provider()` reads `DNS_PROVIDER` setting and returns the appropriate class:
- `cloudflare` → `CloudflareDnsProvider` (requires `cloudflare` extra)
- `route53` → `Route53DnsProvider` (requires `boto3` extra)
- `google` → `GoogleCloudDnsProvider` (requires `google-cloud-dns` extra)

Install the matching extra: `uv sync --extra dns-cloudflare` (or `dns-route53`, `dns-google`, `dns-all`).

**How to apply:** DNS propagation delay is configured via `DNS_PROPAGATION_SECONDS` (default 60s). Never reduce this below the TTL of the DNS zone. The challenge node waits this duration before notifying the ACME server to validate.
