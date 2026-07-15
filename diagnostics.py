"""Active diagnosis for a failed ACME challenge — extracted from
.claude/skills/enroll-cert/SKILL.md step 3 so the same dig/curl logic is
callable programmatically (by the TUI's RunScreen failure panel) instead of
existing only as prose instructions for Claude to execute by hand.

Keep this module's behavior in sync with SKILL.md step 3 — that file should
summarize this module's approach and point here rather than re-deriving it,
so the two don't drift apart.

Fatal-error substrings mirror agent/nodes/error_handler.py's own
_FATAL_ERROR_PATTERNS exactly (not re-derived) — these are unretryable and no
amount of DNS/HTTP diagnosis will fix them.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

from agent.nodes.error_handler import _FATAL_ERROR_PATTERNS, _is_fatal_error

_DIG_TIMEOUT = 10
_CURL_TIMEOUT = 10

# ACME error urn suffixes (RFC 8555 §6.7) this module knows how to explain in
# plain English, beyond error_handler's narrower _FATAL_ERROR_PATTERNS (which
# only covers the subset that changes *retry* behavior — this list is display
# diagnosis only and must never feed back into retry/abort decisions, per
# CLAUDE.md: "Retry logic lives only in error_handler + retry_scheduler").
_ACME_ERROR_URN_RE = re.compile(r"urn:ietf:params:acme:error:(\w+)")

_KNOWN_ACME_ERRORS: dict[str, tuple[str, str]] = {
    "rejectedidentifier": (
        "The CA refuses to issue for this domain, by policy",
        "This is not a transient failure and retrying will not help. Common "
        "causes: (1) the domain is an IANA-reserved documentation name like "
        "example.com/example.org/example.net — these can never be issued for "
        "by any public CA; (2) the domain is on the CA's internal denylist "
        "(phishing/abuse); (3) the TLD isn't supported by this CA. Next step: "
        "set MANAGED_DOMAINS to a real domain you control and own, then retry.",
    ),
    "malformed": (
        "The CA rejected the request as malformed",
        "The ACME request itself (JWS, CSR, or order payload) didn't parse or "
        "didn't match RFC 8555's expected shape — this points at a client-side "
        "bug, not a DNS/network issue. Next step: check the full error detail "
        "text below for which field was rejected; do not retry blindly.",
    ),
    "ratelimited": (
        "The CA's rate limit was hit for this account or domain",
        "Public CAs cap issuances per domain/account per time window (Let's "
        "Encrypt: 5 duplicate certs/week, 300 new orders/account/3h at time of "
        "writing). Next step: wait for the window to reset — retrying "
        "immediately will fail again. If this happens repeatedly, batch fewer "
        "domains per run or switch to letsencrypt_staging for testing.",
    ),
    "caa": (
        "A CAA DNS record is blocking this CA from issuing",
        "The domain's CAA record whitelists a different certificate authority. "
        "Next step: check `dig CAA <domain>` and either add an issue entry for "
        "this CA or switch CA_PROVIDER to the one the CAA record allows.",
    ),
    "connection": (
        "The CA couldn't reach this server to validate the challenge",
        "The CA's validation servers timed out or got refused connecting to "
        "this domain. Next step: run the HTTP-01/DNS-01 diagnosis for this "
        "domain's challenge mode to confirm reachability from the public "
        "internet (not just locally).",
    ),
    "dns": (
        "The CA's DNS lookup for this domain failed",
        "The CA couldn't resolve a required DNS record (A/AAAA for HTTP-01, "
        "TXT for DNS-01) for this domain at all. Next step: confirm the domain "
        "has a public DNS zone and the expected record type exists — `dig "
        "<domain> A` / `dig TXT _acme-challenge.<domain>`.",
    ),
}


def diagnose_known_acme_error(error_text: str) -> DiagnosisResult | None:
    """Plain-English explanation for any RFC 8555 error urn this module
    recognizes, independent of error_handler's retry-fatal subset. Returns
    None if no known urn is found — caller falls through to challenge-type
    diagnosis or a raw-tail fallback."""
    match = _ACME_ERROR_URN_RE.search(error_text.lower())
    if match is None:
        return None
    urn_type = match.group(1)
    known = _KNOWN_ACME_ERRORS.get(urn_type)
    if known is None:
        return None
    title, explanation = known
    return DiagnosisResult(summary=f"{title}.\n\n{explanation}", details=[error_text])


@dataclass
class DiagnosisResult:
    summary: str
    """One plain-English sentence a non-technical user can act on."""
    details: list[str] = field(default_factory=list)
    """Raw command output / intermediate findings, for the EventFeed/verbose view."""


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    """Run a diagnostic subprocess, tolerating a missing binary or timeout
    rather than raising — diagnosis should degrade gracefully, not crash the
    failure panel it's trying to populate."""
    if shutil.which(cmd[0]) is None:
        return (127, "", f"{cmd[0]}: not installed")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (proc.returncode, proc.stdout.strip(), proc.stderr.strip())
    except subprocess.TimeoutExpired:
        return (124, "", f"{' '.join(cmd)}: timed out after {timeout}s")


def diagnose_fatal_error(error_text: str) -> DiagnosisResult | None:
    """Plain-English explanation for error_handler's fatal-error substrings.

    Returns None if error_text doesn't match a known fatal pattern — caller
    should fall through to challenge-type diagnosis in that case.
    """
    if not _is_fatal_error(error_text):
        return None
    lower = error_text.lower()
    if "unauthorized" in lower:
        return DiagnosisResult(
            summary=(
                "The CA rejected proof of domain ownership — this is often the "
                "terminal error text for a challenge that failed validation. "
                "Run the HTTP-01/DNS-01 diagnosis for the challenge mode this "
                "domain uses to find the underlying cause."
            ),
        )
    if "accountdoesnotexist" in lower or "badkey" in lower:
        return DiagnosisResult(
            summary=(
                "The local ACME account key is stale or corrupted for this CA. "
                "The fix is deleting ACCOUNT_KEY_PATH and letting the agent "
                "register a fresh account on the next run — confirm before "
                "deleting anything."
            ),
        )
    if "externalaccountrequired" in lower:
        return DiagnosisResult(
            summary=(
                "This CA requires External Account Binding (EAB) credentials "
                "that are missing or wrong — set ACME_EAB_KEY_ID and "
                "ACME_EAB_HMAC_KEY."
            ),
        )
    # Matched _FATAL_ERROR_PATTERNS but none of the specific substrings above
    # (shouldn't happen unless _FATAL_ERROR_PATTERNS grows a new pattern this
    # function hasn't been taught to explain yet).
    return DiagnosisResult(
        summary=(
            f"A fatal, unretryable error occurred ({', '.join(_FATAL_ERROR_PATTERNS)} "
            "substring matched) — check the full error text for specifics."
        ),
    )


def diagnose_http01(domain: str, token: str, port: int = 80) -> DiagnosisResult:
    """HTTP-01 reachability diagnosis (standalone or webroot mode)."""
    details: list[str] = []
    url = f"http://{domain}/.well-known/acme-challenge/{token}"
    scheme = "" if port == 80 else f":{port}"
    if port != 80:
        url = f"http://{domain}{scheme}/.well-known/acme-challenge/{token}"

    code, body, err = _run(
        ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", str(_CURL_TIMEOUT), url],
        timeout=_CURL_TIMEOUT + 2,
    )
    details.append(f"curl {url} -> exit={code} http_code={body!r} stderr={err!r}")

    a_code, a_out, a_err = _run(["dig", "+short", domain, "A"], timeout=_DIG_TIMEOUT)
    details.append(f"dig {domain} A -> {a_out!r} (stderr={a_err!r})")

    if code != 0 or body in ("", "000"):
        summary = (
            f"Port {port} on {domain} isn't reachable from here — check that a "
            "firewall/router isn't blocking it, and that nothing else already "
            "owns that port locally (standalone mode needs to bind it)."
        )
    elif body == "404":
        summary = (
            "The CA's request reached your server but got a 404 — in webroot "
            "mode, the challenge file didn't land in WEBROOT_PATH, or the web "
            "server isn't serving .well-known/acme-challenge/ from that root."
        )
    elif body == "200":
        summary = (
            "The path is reachable and returned 200, but validation still "
            "failed — check for a redirect rule or catch-all route intercepting "
            "the path before the CA's own (unauthenticated, HTTP-only) request."
        )
    else:
        summary = f"Unexpected HTTP {body} from the challenge path — check server logs directly."

    if not a_out:
        summary += (
            f" Also: `dig {domain} A` returned nothing — confirm the domain's "
            "DNS actually points at this server's public IP at all."
        )

    return DiagnosisResult(summary=summary, details=details)


def diagnose_dns01(domain: str, expected_txt_value: str | None = None) -> DiagnosisResult:
    """DNS-01 TXT record diagnosis (dns mode)."""
    details: list[str] = []
    record = f"_acme-challenge.{domain}"

    code, out, err = _run(["dig", "+short", "TXT", record], timeout=_DIG_TIMEOUT)
    details.append(f"dig TXT {record} -> {out!r} (stderr={err!r})")

    pub_code, pub_out, pub_err = _run(["dig", "@8.8.8.8", "+short", "TXT", record], timeout=_DIG_TIMEOUT)
    details.append(f"dig @8.8.8.8 TXT {record} -> {pub_out!r} (stderr={pub_err!r})")

    values = [line.strip('"') for line in out.splitlines() if line.strip()]

    if not values:
        summary = (
            f"No TXT record found at {record} — the DNS provider API call "
            "likely failed silently, or the configured zone ID doesn't match "
            "this domain's real zone."
        )
    elif expected_txt_value and expected_txt_value not in values:
        summary = (
            f"A TXT record exists at {record} but doesn't match the expected "
            "value — likely a stale record from a prior failed run that wasn't "
            "cleaned up. Multiple TXT values can coexist; check all of them."
        )
    elif out != pub_out:
        summary = (
            f"The TXT record at {record} looks correct locally but a public "
            "resolver (8.8.8.8) sees something different — this is still "
            "propagating. Retry in a few minutes rather than changing config."
        )
    else:
        summary = (
            f"The TXT record at {record} looks correct and propagated — if "
            "validation still failed, the underlying cause may be elsewhere "
            "(check the full error text)."
        )

    return DiagnosisResult(summary=summary, details=details)


def diagnose(
    *,
    error_text: str,
    domain: str,
    challenge_mode: str,
    token: str | None = None,
    port: int = 80,
    expected_txt_value: str | None = None,
) -> DiagnosisResult:
    """Entry point: dispatches to the right diagnosis based on error text and
    challenge mode. Fatal errors short-circuit challenge-type diagnosis."""
    fatal = diagnose_fatal_error(error_text)
    if fatal is not None:
        return fatal

    if challenge_mode == "dns":
        return diagnose_dns01(domain, expected_txt_value)
    # standalone or webroot
    return diagnose_http01(domain, token or "", port)
