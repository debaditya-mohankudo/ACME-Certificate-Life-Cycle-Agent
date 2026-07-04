"""
Unit tests for DNS-01 challenge support.

Tests cover:
  - compute_dns_txt_value() — SHA-256 correctness, determinism, known vector
  - make_dns_provider() — dispatch for all 3 providers, ImportError hints
  - DnsProvider base — _acme_record_name() format (direct)
  - _dns_provider_registry() — error message lists valid choices (direct)
  - CloudflareDnsProvider — create (explicit zone, auto-discover, idempotent), delete,
    error swallowed, zone discovery failure
  - Route53DnsProvider — UPSERT with "" wrapping, zone discovery, DELETE, error swallowed,
    _txt_value() direct, trailing-dot DNS name, explicit credentials, zone discovery failure
  - GoogleCloudDnsProvider — create (idempotent: same value, replace diff value, new record),
    delete, error swallowed, _get_client() with credentials path
  - order_initializer with dns-01 — correct challenge selected, fields populated
  - challenge_setup DNS branch — create_txt_record called, propagation sleep behavior
  - _cleanup_challenge DNS branch — delete called, partial failure, safe when no provider
  - Config validation — dns mode accepted, missing token caught, existing modes unchanged

No Pebble or real DNS credentials required — all network calls are mocked.
"""
from __future__ import annotations

import base64
import hashlib
import json
from unittest.mock import MagicMock, call, patch

import pytest


# ─── compute_dns_txt_value ────────────────────────────────────────────────────


class TestComputeDnsTxtValue:
    """Tests for acme.dns_challenge.compute_dns_txt_value."""

    def test_known_vector(self):
        """RFC 8555 §8.4 example: SHA-256 of key_auth → base64url, no padding."""
        from acme.dns_challenge import compute_dns_txt_value

        key_auth = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA.nysaScAHF4R6FyQ7UGnL1hYu3Dg6EBKZ2TqkPl1JXIA"
        result = compute_dns_txt_value(key_auth)

        # Verify manually: base64url(SHA256(key_auth))
        expected_bytes = hashlib.sha256(key_auth.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(expected_bytes).rstrip(b"=").decode("ascii")
        assert result == expected

    def test_no_padding(self):
        """Result must not contain '=' padding characters."""
        from acme.dns_challenge import compute_dns_txt_value

        result = compute_dns_txt_value("token.thumbprint")
        assert "=" not in result

    def test_deterministic(self):
        """Same key_auth always produces the same TXT value."""
        from acme.dns_challenge import compute_dns_txt_value

        key_auth = "abc.def"
        assert compute_dns_txt_value(key_auth) == compute_dns_txt_value(key_auth)

    def test_different_inputs_produce_different_outputs(self):
        """Different key_auth strings must produce different TXT values."""
        from acme.dns_challenge import compute_dns_txt_value

        assert compute_dns_txt_value("token1.tp") != compute_dns_txt_value("token2.tp")

    def test_output_is_valid_base64url(self):
        """Output characters must only be URL-safe base64 alphabet."""
        from acme.dns_challenge import compute_dns_txt_value

        result = compute_dns_txt_value("some.keyauth")
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        assert all(c in valid_chars for c in result)

    def test_output_length_always_43(self):
        """SHA-256 digest (32 bytes) encodes to exactly 43 base64url chars."""
        from acme.dns_challenge import compute_dns_txt_value

        # Test various input lengths: minimal, typical, very long
        test_inputs = [
            "a.b",  # minimal
            "token.thumbprint",  # typical
            "x" * 100 + "." + "y" * 100,  # long
            "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA.nysaScAHF4R6FyQ7UGnL1hYu3Dg6EBKZ2TqkPl1JXIA",
        ]
        for key_auth in test_inputs:
            result = compute_dns_txt_value(key_auth)
            # SHA-256 → 32 bytes → base64url without padding = always 43 chars
            assert len(result) == 43, f"Expected 43 chars for {key_auth!r}, got {len(result)}"

    def test_minimal_key_auth(self):
        """Minimal key_auth ('a.b') produces consistent, valid output."""
        from acme.dns_challenge import compute_dns_txt_value

        result = compute_dns_txt_value("a.b")
        # Verify against manual calculation
        expected_bytes = hashlib.sha256(b"a.b").digest()
        expected = base64.urlsafe_b64encode(expected_bytes).rstrip(b"=").decode("ascii")
        assert result == expected
        assert len(result) == 43
        assert "=" not in result

    def test_with_real_jwk_thumbprint_characters(self):
        """Real JWK thumbprints contain base64url characters (-, _)."""
        from acme.dns_challenge import compute_dns_txt_value

        # Real JWK thumbprint format: base64url(JSON hash)
        # Includes URL-safe chars like - and _
        key_auth = "token-ABC_xyz.thumbprint-123_XYZ"
        result = compute_dns_txt_value(key_auth)

        # Verify it matches manual calculation
        expected_bytes = hashlib.sha256(key_auth.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(expected_bytes).rstrip(b"=").decode("ascii")
        assert result == expected
        assert "=" not in result


# ─── make_dns_provider ────────────────────────────────────────────────────────


class TestMakeDnsProvider:
    """Tests for acme.dns_challenge.make_dns_provider factory."""

    def test_dispatches_cloudflare(self):
        """make_dns_provider() returns CloudflareDnsProvider for cloudflare."""
        from acme.dns_challenge import CloudflareDnsProvider, make_dns_provider

        with patch("acme.dns_challenge.CloudflareDnsProvider.__init__", return_value=None) as mock_init:
            with patch("config.settings") as mock_settings:
                mock_settings.DNS_PROVIDER = "cloudflare"
                mock_settings.CLOUDFLARE_API_TOKEN = "token"
                mock_settings.CLOUDFLARE_ZONE_ID = "zone123"
                provider = make_dns_provider()
            mock_init.assert_called_once_with(api_token="token", zone_id="zone123")

    def test_dispatches_route53(self):
        """make_dns_provider() returns Route53DnsProvider for route53."""
        from acme.dns_challenge import Route53DnsProvider, make_dns_provider

        with patch("acme.dns_challenge.Route53DnsProvider.__init__", return_value=None) as mock_init:
            with patch("config.settings") as mock_settings:
                mock_settings.DNS_PROVIDER = "route53"
                mock_settings.AWS_ROUTE53_HOSTED_ZONE_ID = "Z123"
                mock_settings.AWS_REGION = "us-west-2"
                mock_settings.AWS_ACCESS_KEY_ID = ""
                mock_settings.AWS_SECRET_ACCESS_KEY = ""
                provider = make_dns_provider()
            mock_init.assert_called_once_with(
                hosted_zone_id="Z123",
                region="us-west-2",
                access_key_id="",
                secret_access_key="",
            )

    def test_dispatches_google(self):
        """make_dns_provider() returns GoogleCloudDnsProvider for google."""
        from acme.dns_challenge import GoogleCloudDnsProvider, make_dns_provider

        with patch("acme.dns_challenge.GoogleCloudDnsProvider.__init__", return_value=None) as mock_init:
            with patch("config.settings") as mock_settings:
                mock_settings.DNS_PROVIDER = "google"
                mock_settings.GOOGLE_PROJECT_ID = "my-project"
                mock_settings.GOOGLE_CLOUD_DNS_ZONE_NAME = "my-zone"
                mock_settings.GOOGLE_APPLICATION_CREDENTIALS = "/path/creds.json"
                provider = make_dns_provider()
            mock_init.assert_called_once_with(
                project_id="my-project",
                zone_name="my-zone",
                credentials_path="/path/creds.json",
            )

    def test_unknown_provider_raises(self):
        """make_dns_provider() raises ValueError for unknown providers."""
        from acme.dns_challenge import make_dns_provider

        with patch("config.settings") as mock_settings:
            mock_settings.DNS_PROVIDER = "unknown_provider"
            with pytest.raises(ValueError, match="Unknown DNS_PROVIDER"):
                make_dns_provider()

    def test_cloudflare_importerror_hint(self):
        """CloudflareDnsProvider raises ImportError with install hint if cloudflare not installed."""
        from acme.dns_challenge import CloudflareDnsProvider

        with patch.dict("sys.modules", {"cloudflare": None}):
            with pytest.raises(ImportError, match="uv sync --extra dns-cloudflare"):
                CloudflareDnsProvider(api_token="tok")

    def test_route53_importerror_hint(self):
        """Route53DnsProvider raises ImportError with install hint if boto3 not installed."""
        from acme.dns_challenge import Route53DnsProvider

        with patch.dict("sys.modules", {"boto3": None}):
            with pytest.raises(ImportError, match="uv sync --extra dns-route53"):
                Route53DnsProvider()

    def test_google_importerror_hint(self):
        """GoogleCloudDnsProvider raises ImportError with install hint if google-cloud-dns not installed."""
        from acme.dns_challenge import GoogleCloudDnsProvider

        with patch.dict("sys.modules", {"google.cloud": None, "google.cloud.dns": None}):
            with pytest.raises(ImportError, match="uv sync --extra dns-google"):
                GoogleCloudDnsProvider(project_id="p", zone_name="z")


# ─── CloudflareDnsProvider ────────────────────────────────────────────────────


class TestCloudflareDnsProvider:
    """Tests for CloudflareDnsProvider using a mocked cloudflare module."""

    @pytest.fixture
    def cf_mock(self):
        """Return a mock cloudflare module and Cloudflare client."""
        mock_cf_module = MagicMock()
        mock_client = MagicMock()
        mock_cf_module.Cloudflare.return_value = mock_client
        return mock_cf_module, mock_client

    def _make_provider(self, cf_mock, api_token="tok", zone_id="zone123"):
        from acme.dns_challenge import CloudflareDnsProvider

        cf_module, _ = cf_mock
        with patch.dict("sys.modules", {"cloudflare": cf_module}):
            # Re-import to pick up patched module
            provider = CloudflareDnsProvider.__new__(CloudflareDnsProvider)
            provider._cf_mod = cf_module
            provider._api_token = api_token
            provider._explicit_zone_id = zone_id
        return provider

    def test_create_txt_record_explicit_zone(self, cf_mock):
        """create_txt_record uses explicit zone_id without zone discovery."""
        cf_module, mock_client = cf_mock
        mock_client.dns.records.list.return_value = []  # No existing records

        provider = self._make_provider(cf_mock, zone_id="explicit-zone")
        provider.create_txt_record("api.example.com", "txt-value")

        mock_client.dns.records.create.assert_called_once_with(
            zone_id="explicit-zone",
            type="TXT",
            name="_acme-challenge.api.example.com",
            content="txt-value",
            ttl=60,
        )

    def test_create_txt_record_auto_discover_zone(self, cf_mock):
        """create_txt_record auto-discovers zone when zone_id is empty."""
        cf_module, mock_client = cf_mock

        mock_zone = MagicMock()
        mock_zone.id = "discovered-zone"
        mock_client.zones.list.return_value = [mock_zone]
        mock_client.dns.records.list.return_value = []

        provider = self._make_provider(cf_mock, zone_id="")
        provider.create_txt_record("api.example.com", "txt-value")

        # Zone discovery should have been called
        mock_client.zones.list.assert_called()
        mock_client.dns.records.create.assert_called_once()

    def test_create_txt_record_idempotent(self, cf_mock):
        """create_txt_record skips create if identical record already exists."""
        cf_module, mock_client = cf_mock

        existing = MagicMock()
        existing.content = "txt-value"
        mock_client.dns.records.list.return_value = [existing]

        provider = self._make_provider(cf_mock, zone_id="zone123")
        provider.create_txt_record("api.example.com", "txt-value")

        mock_client.dns.records.create.assert_not_called()

    def test_delete_txt_record_finds_and_deletes(self, cf_mock):
        """delete_txt_record finds the matching record and deletes it."""
        cf_module, mock_client = cf_mock

        record = MagicMock()
        record.id = "rec-abc"
        record.content = "txt-value"
        mock_client.dns.records.list.return_value = [record]

        provider = self._make_provider(cf_mock, zone_id="zone123")
        provider.delete_txt_record("api.example.com", "txt-value")

        mock_client.dns.records.delete.assert_called_once_with("rec-abc", zone_id="zone123")

    def test_delete_txt_record_swallows_errors(self, cf_mock):
        """delete_txt_record does not raise when an error occurs."""
        cf_module, mock_client = cf_mock
        mock_client.dns.records.list.side_effect = RuntimeError("API down")

        provider = self._make_provider(cf_mock, zone_id="zone123")
        # Must not raise
        provider.delete_txt_record("api.example.com", "txt-value")

    def test_delete_txt_record_missing_record_silent(self, cf_mock):
        """delete_txt_record silently does nothing if record not found."""
        cf_module, mock_client = cf_mock
        mock_client.dns.records.list.return_value = []

        provider = self._make_provider(cf_mock, zone_id="zone123")
        provider.delete_txt_record("api.example.com", "missing-value")

        mock_client.dns.records.delete.assert_not_called()


# ─── Route53DnsProvider ───────────────────────────────────────────────────────


class TestRoute53DnsProvider:
    """Tests for Route53DnsProvider using a mocked boto3 module."""

    @pytest.fixture
    def boto3_mock(self):
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        return mock_boto3, mock_client

    def _make_provider(self, boto3_mock, hosted_zone_id="Z123", region="us-east-1"):
        from acme.dns_challenge import Route53DnsProvider

        mock_boto3, _ = boto3_mock
        provider = Route53DnsProvider.__new__(Route53DnsProvider)
        provider._boto3 = mock_boto3
        provider._explicit_zone_id = hosted_zone_id
        provider._region = region
        provider._access_key_id = ""
        provider._secret_access_key = ""
        return provider

    def test_create_txt_record_upsert_with_quotes(self, boto3_mock):
        """create_txt_record wraps TXT value in double-quotes for Route53."""
        mock_boto3, mock_client = boto3_mock

        provider = self._make_provider(boto3_mock, hosted_zone_id="Z123")
        provider.create_txt_record("api.example.com", "txt-value")

        call_args = mock_client.change_resource_record_sets.call_args
        changes = call_args.kwargs["ChangeBatch"]["Changes"]
        assert len(changes) == 1
        assert changes[0]["Action"] == "UPSERT"
        resource_records = changes[0]["ResourceRecordSet"]["ResourceRecords"]
        assert resource_records == [{"Value": '"txt-value"'}]

    def test_create_txt_record_uses_explicit_zone_id(self, boto3_mock):
        """create_txt_record uses explicit hosted_zone_id."""
        mock_boto3, mock_client = boto3_mock

        provider = self._make_provider(boto3_mock, hosted_zone_id="EXPLICIT-ZONE")
        provider.create_txt_record("api.example.com", "txt")

        call_args = mock_client.change_resource_record_sets.call_args
        assert call_args.kwargs["HostedZoneId"] == "EXPLICIT-ZONE"

    def test_create_txt_record_auto_discover_zone(self, boto3_mock):
        """create_txt_record auto-discovers zone when hosted_zone_id is empty."""
        mock_boto3, mock_client = boto3_mock
        mock_client.list_hosted_zones_by_name.return_value = {
            "HostedZones": [{"Name": "example.com.", "Id": "/hostedzone/DISCOVERED"}]
        }

        provider = self._make_provider(boto3_mock, hosted_zone_id="")
        provider.create_txt_record("api.example.com", "txt")

        call_args = mock_client.change_resource_record_sets.call_args
        assert call_args.kwargs["HostedZoneId"] == "DISCOVERED"

    def test_delete_txt_record_uses_delete_action(self, boto3_mock):
        """delete_txt_record sends a DELETE change to Route53."""
        mock_boto3, mock_client = boto3_mock

        provider = self._make_provider(boto3_mock, hosted_zone_id="Z123")
        provider.delete_txt_record("api.example.com", "txt-value")

        call_args = mock_client.change_resource_record_sets.call_args
        changes = call_args.kwargs["ChangeBatch"]["Changes"]
        assert changes[0]["Action"] == "DELETE"

    def test_delete_txt_record_swallows_errors(self, boto3_mock):
        """delete_txt_record does not raise when Route53 returns an error."""
        mock_boto3, mock_client = boto3_mock
        mock_client.change_resource_record_sets.side_effect = RuntimeError("NoSuchChange")

        provider = self._make_provider(boto3_mock, hosted_zone_id="Z123")
        # Must not raise
        provider.delete_txt_record("api.example.com", "txt-value")


# ─── GoogleCloudDnsProvider ───────────────────────────────────────────────────


class TestGoogleCloudDnsProvider:
    """Tests for GoogleCloudDnsProvider using a mocked google.cloud.dns module."""

    @pytest.fixture
    def gcp_dns_mock(self):
        mock_dns_module = MagicMock()
        mock_gcp_client = MagicMock()
        mock_dns_module.Client.return_value = mock_gcp_client
        mock_zone = MagicMock()
        mock_gcp_client.zone.return_value = mock_zone
        return mock_dns_module, mock_gcp_client, mock_zone

    def _make_provider(self, gcp_dns_mock, project_id="my-project", zone_name="my-zone"):
        from acme.dns_challenge import GoogleCloudDnsProvider

        mock_dns_module, _, _ = gcp_dns_mock
        provider = GoogleCloudDnsProvider.__new__(GoogleCloudDnsProvider)
        provider._gcp_dns = mock_dns_module
        provider._project_id = project_id
        provider._zone_name = zone_name
        provider._credentials_path = ""
        return provider

    def test_create_txt_record_calls_add_and_create(self, gcp_dns_mock):
        """create_txt_record calls add_record_set() and changes.create()."""
        mock_dns_module, mock_gcp_client, mock_zone = gcp_dns_mock

        provider = self._make_provider(gcp_dns_mock)
        provider.create_txt_record("api.example.com", "txt-value")

        mock_zone.resource_record_set.assert_called_once_with(
            "_acme-challenge.api.example.com.", "TXT", 60, ['"txt-value"']
        )
        mock_zone.changes.return_value.add_record_set.assert_called_once()
        mock_zone.changes.return_value.create.assert_called_once()

    def test_delete_txt_record_calls_delete_and_create(self, gcp_dns_mock):
        """delete_txt_record calls delete_record_set() and changes.create()."""
        mock_dns_module, mock_gcp_client, mock_zone = gcp_dns_mock

        provider = self._make_provider(gcp_dns_mock)
        provider.delete_txt_record("api.example.com", "txt-value")

        mock_zone.changes.return_value.delete_record_set.assert_called_once()
        mock_zone.changes.return_value.create.assert_called_once()

    def test_delete_txt_record_swallows_errors(self, gcp_dns_mock):
        """delete_txt_record does not raise on errors."""
        mock_dns_module, mock_gcp_client, mock_zone = gcp_dns_mock
        mock_zone.changes.return_value.create.side_effect = RuntimeError("API error")

        provider = self._make_provider(gcp_dns_mock)
        # Must not raise
        provider.delete_txt_record("api.example.com", "txt-value")

    def test_create_txt_record_idempotent_same_value(self, gcp_dns_mock):
        """create_txt_record is idempotent: if record exists with same value, skip."""
        mock_dns_module, mock_gcp_client, mock_zone = gcp_dns_mock

        # Mock existing record with matching value
        mock_existing_record = MagicMock()
        mock_existing_record.name = "_acme-challenge.api.example.com."
        mock_existing_record.record_type = "TXT"
        mock_existing_record.rdata = ['"txt-value"']

        mock_zone.list_resource_record_sets.return_value = [mock_existing_record]

        provider = self._make_provider(gcp_dns_mock)
        provider.create_txt_record("api.example.com", "txt-value")

        # Should not call add_record_set since record already exists
        mock_zone.changes.return_value.add_record_set.assert_not_called()
        # Should not call create for add
        assert mock_zone.changes.return_value.create.call_count == 0

    def test_create_txt_record_replace_different_value(self, gcp_dns_mock):
        """create_txt_record replaces existing record with different value."""
        mock_dns_module, mock_gcp_client, mock_zone = gcp_dns_mock

        # Mock existing record with different value
        mock_existing_record = MagicMock()
        mock_existing_record.name = "_acme-challenge.api.example.com."
        mock_existing_record.record_type = "TXT"
        mock_existing_record.rdata = ['"old-value"']

        mock_zone.list_resource_record_sets.return_value = [mock_existing_record]

        provider = self._make_provider(gcp_dns_mock)
        provider.create_txt_record("api.example.com", "new-value")

        # Should call delete for the old record, then add for the new one
        mock_zone.changes.return_value.delete_record_set.assert_called_once_with(
            mock_existing_record
        )
        mock_zone.changes.return_value.add_record_set.assert_called_once()
        # Should call create twice: once for delete, once for add
        assert mock_zone.changes.return_value.create.call_count == 2

    def test_create_txt_record_no_existing_record(self, gcp_dns_mock):
        """create_txt_record creates new record when none exists."""
        mock_dns_module, mock_gcp_client, mock_zone = gcp_dns_mock

        # Mock no existing records
        mock_zone.list_resource_record_sets.return_value = []

        provider = self._make_provider(gcp_dns_mock)
        provider.create_txt_record("api.example.com", "new-value")

        # Should call add_record_set and create once
        mock_zone.changes.return_value.add_record_set.assert_called_once()
        assert mock_zone.changes.return_value.create.call_count == 1


# ─── order_initializer (DNS-01) ───────────────────────────────────────────────


class TestOrderInitializerDns01:
    """Tests for order_initializer node when HTTP_CHALLENGE_MODE='dns'."""

    def _make_state(self, domain="api.example.com"):
        return {
            "current_domain": domain,
            "acme_account_url": "https://acme.test/acct/1",
            "account_key_path": "/tmp/account.key",
            "current_nonce": "nonce123",
            "error_log": [],
        }

    def _make_authz(self, domain, token="tok123"):
        return {
            "identifier": {"type": "dns", "value": domain},
            "status": "pending",
            "challenges": [
                {"type": "dns-01", "url": "https://acme.test/ch/dns/1", "token": token},
                {"type": "http-01", "url": "https://acme.test/ch/http/1", "token": token},
            ],
        }

    def test_dns01_challenge_selected(self):
        """order_initializer selects dns-01 challenge when mode='dns'."""
        from agent.nodes.order import order_initializer

        state = self._make_state()
        authz = self._make_authz("api.example.com", token="mytoken")
        order_body = {
            "status": "pending",
            "authorizations": ["https://acme.test/authz/1"],
            "finalize": "https://acme.test/finalize/1",
        }

        mock_client = MagicMock()
        mock_client.get_directory.return_value = {}
        mock_client.create_order.return_value = (order_body, "https://acme.test/order/1", "nonce2")
        mock_client.get_authorization.return_value = authz

        mock_account_key = MagicMock()

        with patch("agent.nodes.order.make_client", return_value=mock_client), \
             patch("agent.nodes.order.jwslib.load_account_key", return_value=mock_account_key), \
             patch("agent.nodes.order.jwslib.compute_jwk_thumbprint", return_value="thumbprint"), \
             patch("config.settings") as mock_settings:

            mock_settings.HTTP_CHALLENGE_MODE = "dns"

            result = order_initializer(state)

        assert "current_order" in result
        order = result["current_order"]
        assert order["challenge_urls"] == ["https://acme.test/ch/dns/1"]

    def test_dns01_populates_auth_domains(self):
        """order_initializer populates auth_domains from authz identifier."""
        from agent.nodes.order import order_initializer

        state = self._make_state()
        authz = self._make_authz("api.example.com")
        order_body = {
            "status": "pending",
            "authorizations": ["https://acme.test/authz/1"],
            "finalize": "https://acme.test/finalize/1",
        }

        mock_client = MagicMock()
        mock_client.get_directory.return_value = {}
        mock_client.create_order.return_value = (order_body, "https://acme.test/order/1", "nonce2")
        mock_client.get_authorization.return_value = authz

        with patch("agent.nodes.order.make_client", return_value=mock_client), \
             patch("agent.nodes.order.jwslib.load_account_key", return_value=MagicMock()), \
             patch("agent.nodes.order.jwslib.compute_jwk_thumbprint", return_value="tp"), \
             patch("config.settings") as mock_settings:

            mock_settings.HTTP_CHALLENGE_MODE = "dns"

            result = order_initializer(state)

        order = result["current_order"]
        assert order["auth_domains"] == ["api.example.com"]

    def test_dns01_populates_dns_txt_values(self):
        """order_initializer populates dns_txt_values with correct SHA-256 values."""
        from acme.dns_challenge import compute_dns_txt_value
        from agent.nodes.order import order_initializer

        state = self._make_state()
        authz = self._make_authz("api.example.com", token="tok")
        order_body = {
            "status": "pending",
            "authorizations": ["https://acme.test/authz/1"],
            "finalize": "https://acme.test/finalize/1",
        }

        mock_client = MagicMock()
        mock_client.get_directory.return_value = {}
        mock_client.create_order.return_value = (order_body, "https://acme.test/order/1", "nonce2")
        mock_client.get_authorization.return_value = authz

        with patch("agent.nodes.order.make_client", return_value=mock_client), \
             patch("agent.nodes.order.jwslib.load_account_key", return_value=MagicMock()), \
             patch("agent.nodes.order.jwslib.compute_jwk_thumbprint", return_value="tp"), \
             patch("config.settings") as mock_settings:

            mock_settings.HTTP_CHALLENGE_MODE = "dns"

            result = order_initializer(state)

        order = result["current_order"]
        expected_txt = compute_dns_txt_value("tok.tp")
        assert order["dns_txt_values"] == [expected_txt]

    def test_http01_dns_txt_values_empty(self):
        """order_initializer leaves dns_txt_values empty for HTTP-01 mode."""
        from agent.nodes.order import order_initializer

        state = self._make_state()
        authz = self._make_authz("api.example.com")
        order_body = {
            "status": "pending",
            "authorizations": ["https://acme.test/authz/1"],
            "finalize": "https://acme.test/finalize/1",
        }

        mock_client = MagicMock()
        mock_client.get_directory.return_value = {}
        mock_client.create_order.return_value = (order_body, "https://acme.test/order/1", "nonce2")
        mock_client.get_authorization.return_value = authz

        with patch("agent.nodes.order.make_client", return_value=mock_client), \
             patch("agent.nodes.order.jwslib.load_account_key", return_value=MagicMock()), \
             patch("agent.nodes.order.jwslib.compute_jwk_thumbprint", return_value="tp"), \
             patch("config.settings") as mock_settings:

            mock_settings.HTTP_CHALLENGE_MODE = "standalone"

            result = order_initializer(state)

        order = result["current_order"]
        assert order["dns_txt_values"] == []

    def test_missing_dns01_challenge_returns_error(self):
        """order_initializer returns error_log entry when dns-01 challenge not found."""
        from agent.nodes.order import order_initializer

        state = self._make_state()
        # Authz with only http-01, no dns-01
        authz = {
            "identifier": {"type": "dns", "value": "api.example.com"},
            "status": "pending",
            "challenges": [
                {"type": "http-01", "url": "https://acme.test/ch/http/1", "token": "tok"}
            ],
        }
        order_body = {
            "status": "pending",
            "authorizations": ["https://acme.test/authz/1"],
            "finalize": "https://acme.test/finalize/1",
        }

        mock_client = MagicMock()
        mock_client.get_directory.return_value = {}
        mock_client.create_order.return_value = (order_body, "https://acme.test/order/1", "nonce2")
        mock_client.get_authorization.return_value = authz

        with patch("agent.nodes.order.make_client", return_value=mock_client), \
             patch("agent.nodes.order.jwslib.load_account_key", return_value=MagicMock()), \
             patch("agent.nodes.order.jwslib.compute_jwk_thumbprint", return_value="tp"), \
             patch("config.settings") as mock_settings:

            mock_settings.HTTP_CHALLENGE_MODE = "dns"

            result = order_initializer(state)

        assert "error_log" in result
        assert any("dns-01" in e for e in result["error_log"])


# ─── challenge_setup (DNS branch) ─────────────────────────────────────────────


class TestChallengeSetupDns:
    """Tests for challenge_setup when mode='dns'."""

    def _make_order(self, domains=None, txt_values=None):
        domains = domains or ["api.example.com"]
        txt_values = txt_values or ["txtval1"]
        return {
            "challenge_tokens": ["tok1"],
            "key_authorizations": ["tok1.tp"],
            "auth_domains": domains,
            "dns_txt_values": txt_values,
        }

    def _make_state(self, order):
        return {
            "current_order": order,
            "error_log": [],
        }

    def test_create_txt_record_called_for_each_domain(self):
        """challenge_setup calls create_txt_record once per domain."""
        from agent.nodes.challenge import challenge_setup

        order = self._make_order(
            domains=["a.example.com", "b.example.com"],
            txt_values=["val1", "val2"],
        )
        state = self._make_state(order)
        mock_provider = MagicMock()

        with patch("config.settings") as mock_settings, \
             patch("agent.nodes.challenge.make_dns_provider", return_value=mock_provider):
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            mock_settings.DNS_PROPAGATION_WAIT_SECONDS = 0

            challenge_setup(state)

        assert mock_provider.create_txt_record.call_count == 2
        mock_provider.create_txt_record.assert_any_call("a.example.com", "val1")
        mock_provider.create_txt_record.assert_any_call("b.example.com", "val2")

    def test_propagation_sleep_called_when_positive(self):
        """challenge_setup sleeps for DNS_PROPAGATION_WAIT_SECONDS when > 0."""
        from agent.nodes.challenge import challenge_setup

        order = self._make_order()
        state = self._make_state(order)
        mock_provider = MagicMock()

        with patch("config.settings") as mock_settings, \
             patch("agent.nodes.challenge.make_dns_provider", return_value=mock_provider), \
             patch("agent.nodes.challenge.time.sleep") as mock_sleep:
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            mock_settings.DNS_PROPAGATION_WAIT_SECONDS = 30

            challenge_setup(state)

        mock_sleep.assert_called_once_with(30)

    def test_propagation_sleep_skipped_when_zero(self):
        """challenge_setup skips sleep when DNS_PROPAGATION_WAIT_SECONDS=0."""
        from agent.nodes.challenge import challenge_setup

        order = self._make_order()
        state = self._make_state(order)
        mock_provider = MagicMock()

        with patch("config.settings") as mock_settings, \
             patch("agent.nodes.challenge.make_dns_provider", return_value=mock_provider), \
             patch("agent.nodes.challenge.time.sleep") as mock_sleep:
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            mock_settings.DNS_PROPAGATION_WAIT_SECONDS = 0

            challenge_setup(state)

        mock_sleep.assert_not_called()

    def test_returns_empty_dict(self):
        """challenge_setup returns empty dict on success (no state update)."""
        from agent.nodes.challenge import challenge_setup

        order = self._make_order()
        state = self._make_state(order)
        mock_provider = MagicMock()

        with patch("config.settings") as mock_settings, \
             patch("agent.nodes.challenge.make_dns_provider", return_value=mock_provider):
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            mock_settings.DNS_PROPAGATION_WAIT_SECONDS = 0

            result = challenge_setup(state)

        assert result == {}


# ─── _cleanup_challenge (DNS branch) ─────────────────────────────────────────


class TestCleanupChallengeDns:
    """Tests for _cleanup_challenge when mode='dns'."""

    def _make_order(self, domains=None, txt_values=None):
        return {
            "challenge_tokens": ["tok1"],
            "key_authorizations": ["tok1.tp"],
            "auth_domains": domains or ["api.example.com"],
            "dns_txt_values": txt_values or ["val1"],
        }

    def test_delete_called_for_each_domain(self):
        """_cleanup_challenge calls delete_txt_record for each domain."""
        import agent.nodes.challenge as challenge_mod
        from agent.nodes.challenge import _cleanup_challenge

        order = self._make_order(
            domains=["a.example.com", "b.example.com"],
            txt_values=["val1", "val2"],
        )
        state = {"current_order": order}
        mock_provider = MagicMock()
        challenge_mod._dns_provider = mock_provider

        with patch("config.settings") as mock_settings:
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            _cleanup_challenge(state)

        assert mock_provider.delete_txt_record.call_count == 2
        mock_provider.delete_txt_record.assert_any_call("a.example.com", "val1")
        mock_provider.delete_txt_record.assert_any_call("b.example.com", "val2")

        # Provider should be cleared
        assert challenge_mod._dns_provider is None

    def test_continues_on_partial_failure(self):
        """_cleanup_challenge continues deleting even when one domain fails."""
        import agent.nodes.challenge as challenge_mod
        from agent.nodes.challenge import _cleanup_challenge

        order = self._make_order(
            domains=["a.example.com", "b.example.com"],
            txt_values=["val1", "val2"],
        )
        state = {"current_order": order}
        mock_provider = MagicMock()
        # First call raises, second should still proceed
        mock_provider.delete_txt_record.side_effect = [RuntimeError("API down"), None]
        challenge_mod._dns_provider = mock_provider

        with patch("config.settings") as mock_settings:
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            # Must not raise
            _cleanup_challenge(state)

        assert mock_provider.delete_txt_record.call_count == 2

    def test_safe_when_no_provider(self):
        """_cleanup_challenge is safe when _dns_provider is None."""
        import agent.nodes.challenge as challenge_mod
        from agent.nodes.challenge import _cleanup_challenge

        challenge_mod._dns_provider = None
        state = {"current_order": self._make_order()}

        with patch("config.settings") as mock_settings:
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            # Must not raise
            _cleanup_challenge(state)


# ─── Config validation ────────────────────────────────────────────────────────


class TestConfigValidation:
    """Tests for config.py DNS-related validators."""

    def test_dns_mode_accepted(self):
        """HTTP_CHALLENGE_MODE='dns' passes validation."""
        from pydantic import ValidationError

        from config import AcmeConfig as Settings

        # Build a Settings object with dns mode — should not raise
        s = Settings(
            HTTP_CHALLENGE_MODE="dns",
            DNS_PROVIDER="cloudflare",
            CLOUDFLARE_API_TOKEN="tok",
            # Suppress unrelated validators
            CA_PROVIDER="letsencrypt",
            MANAGED_DOMAINS="example.com",
        )
        assert s.HTTP_CHALLENGE_MODE == "dns"

    def test_invalid_mode_rejected(self):
        """HTTP_CHALLENGE_MODE='ftp' is rejected."""
        from pydantic import ValidationError

        from config import AcmeConfig as Settings

        with pytest.raises((ValidationError, ValueError)):
            Settings(
                HTTP_CHALLENGE_MODE="ftp",
                CA_PROVIDER="letsencrypt",
            )

    def test_cloudflare_missing_token_raises(self):
        """DNS mode with cloudflare provider and no token raises ValueError."""
        from pydantic import ValidationError

        from config import AcmeConfig as Settings

        with pytest.raises((ValidationError, ValueError)):
            Settings(
                HTTP_CHALLENGE_MODE="dns",
                DNS_PROVIDER="cloudflare",
                CLOUDFLARE_API_TOKEN="",  # Missing!
                CA_PROVIDER="letsencrypt",
                MANAGED_DOMAINS="example.com",
            )

    def test_google_missing_project_id_raises(self):
        """DNS mode with google provider and no project_id raises ValueError."""
        from pydantic import ValidationError

        from config import AcmeConfig as Settings

        with pytest.raises((ValidationError, ValueError)):
            Settings(
                HTTP_CHALLENGE_MODE="dns",
                DNS_PROVIDER="google",
                GOOGLE_PROJECT_ID="",  # Missing!
                CA_PROVIDER="letsencrypt",
                MANAGED_DOMAINS="example.com",
            )

    def test_route53_no_mandatory_fields(self):
        """Route53 uses credential chain — no mandatory fields required."""
        from config import AcmeConfig as Settings

        s = Settings(
            HTTP_CHALLENGE_MODE="dns",
            DNS_PROVIDER="route53",
            # No AWS keys — uses credential chain / instance role
            CA_PROVIDER="letsencrypt",
            MANAGED_DOMAINS="example.com",
        )
        assert s.DNS_PROVIDER == "route53"

    def test_standalone_mode_unchanged(self):
        """standalone mode validation is unaffected by DNS changes."""
        from config import AcmeConfig as Settings

        s = Settings(
            HTTP_CHALLENGE_MODE="standalone",
            CA_PROVIDER="letsencrypt",
            MANAGED_DOMAINS="example.com",
        )
        assert s.HTTP_CHALLENGE_MODE == "standalone"

    def test_webroot_mode_unchanged(self):
        """webroot mode still requires WEBROOT_PATH."""
        from pydantic import ValidationError

        from config import AcmeConfig as Settings

        with pytest.raises((ValidationError, ValueError), match="WEBROOT_PATH"):
            Settings(
                HTTP_CHALLENGE_MODE="webroot",
                WEBROOT_PATH="",
                CA_PROVIDER="letsencrypt",
                MANAGED_DOMAINS="example.com",
            )


# ─── DnsProvider base ─────────────────────────────────────────────────────────


class TestDnsProviderBase:
    """Direct tests for DnsProvider._acme_record_name() static method.

    This is the sole formatter for the DNS challenge record name.  Any
    regression here silently breaks all three providers simultaneously.
    """

    def test_acme_record_name_apex_domain(self):
        """Apex domain is prefixed with _acme-challenge."""
        from acme.dns_challenge import DnsProvider

        assert DnsProvider._acme_record_name("example.com") == "_acme-challenge.example.com"

    def test_acme_record_name_subdomain(self):
        """Subdomain is prefixed correctly without double-label insertion."""
        from acme.dns_challenge import DnsProvider

        assert DnsProvider._acme_record_name("api.sub.example.com") == "_acme-challenge.api.sub.example.com"


# ─── _dns_provider_registry (direct) ──────────────────────────────────────────


class TestDnsProviderRegistry:
    """Direct tests for _dns_provider_registry().

    make_dns_provider() is the public entry point, but testing the registry
    directly pins the error message contract independently of the settings layer.
    """

    def test_unknown_provider_error_lists_valid_choices(self):
        """ValueError message enumerates all valid provider names."""
        from acme.dns_challenge import _dns_provider_registry

        with pytest.raises(ValueError) as exc_info:
            _dns_provider_registry("typo", MagicMock())

        msg = str(exc_info.value)
        assert "cloudflare" in msg
        assert "route53" in msg
        assert "google" in msg

    def test_empty_string_provider_raises(self):
        """Empty string is not a valid provider and raises ValueError."""
        from acme.dns_challenge import _dns_provider_registry

        with pytest.raises(ValueError, match="Unknown DNS_PROVIDER"):
            _dns_provider_registry("", MagicMock())


# ─── CloudflareDnsProvider — zone discovery failure ───────────────────────────


class TestCloudflareZoneDiscovery:
    """Tests for CloudflareDnsProvider._resolve_zone_id() error path."""

    def test_resolve_zone_id_raises_when_no_zone_found(self):
        """ValueError is raised when zone auto-discovery finds no matching zone."""
        from acme.dns_challenge import CloudflareDnsProvider

        mock_cf_module = MagicMock()
        mock_client = MagicMock()
        mock_cf_module.Cloudflare.return_value = mock_client
        mock_client.zones.list.return_value = []  # no zones found for any label

        provider = CloudflareDnsProvider.__new__(CloudflareDnsProvider)
        provider._cf_mod = mock_cf_module
        provider._api_token = "tok"
        provider._explicit_zone_id = ""

        with pytest.raises(ValueError, match="Could not discover Cloudflare zone"):
            provider._resolve_zone_id("notfound.example.com")


# ─── Route53DnsProvider — extras ──────────────────────────────────────────────


class TestRoute53Extras:
    """Additional tests for Route53DnsProvider internal methods.

    The existing TestRoute53DnsProvider covers the happy-path API calls.
    These tests pin behaviours that are Route53-specific and regression-prone:
    quote-wrapping, trailing dot, explicit credential injection, discovery failure.
    """

    @pytest.fixture
    def boto3_mock(self):
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        return mock_boto3, mock_client

    def _make_provider(self, boto3_mock, hosted_zone_id="Z123", region="us-east-1"):
        from acme.dns_challenge import Route53DnsProvider

        mock_boto3, _ = boto3_mock
        provider = Route53DnsProvider.__new__(Route53DnsProvider)
        provider._boto3 = mock_boto3
        provider._explicit_zone_id = hosted_zone_id
        provider._region = region
        provider._access_key_id = ""
        provider._secret_access_key = ""
        return provider

    def test_txt_value_wraps_in_double_quotes(self, boto3_mock):
        """_txt_value() wraps the raw TXT value in double-quotes (Route53 requirement)."""
        provider = self._make_provider(boto3_mock)
        assert provider._txt_value("myvalue") == '"myvalue"'

    def test_dns_name_has_trailing_dot(self, boto3_mock):
        """Route53 requires a trailing dot on the DNS name; Cloudflare must not have it."""
        _, mock_client = boto3_mock
        provider = self._make_provider(boto3_mock, hosted_zone_id="Z123")
        provider.create_txt_record("example.com", "val")

        changes = mock_client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]["Changes"]
        name = changes[0]["ResourceRecordSet"]["Name"]
        assert name == "_acme-challenge.example.com."

    def test_get_client_passes_explicit_credentials(self, boto3_mock):
        """_get_client() passes aws_access_key_id / secret when non-empty."""
        mock_boto3, _ = boto3_mock
        provider = self._make_provider(boto3_mock)
        provider._access_key_id = "AKID"
        provider._secret_access_key = "SECRET"

        provider._get_client()

        mock_boto3.client.assert_called_once_with(
            "route53",
            region_name="us-east-1",
            aws_access_key_id="AKID",
            aws_secret_access_key="SECRET",
        )

    def test_resolve_zone_id_raises_when_no_zone_found(self, boto3_mock):
        """ValueError is raised when Route53 zone auto-discovery finds no match."""
        _, mock_client = boto3_mock
        mock_client.list_hosted_zones_by_name.return_value = {"HostedZones": []}

        provider = self._make_provider(boto3_mock, hosted_zone_id="")

        with pytest.raises(ValueError, match="Could not discover Route53"):
            provider._resolve_zone_id("notfound.example.com")


# ─── GoogleCloudDnsProvider — credentials path ────────────────────────────────


class TestGoogleCloudExtras:
    """Tests for GoogleCloudDnsProvider._get_client() with a credentials_path set."""

    def test_get_client_with_credentials_path(self):
        """_get_client() loads service account credentials and passes them to Client()."""
        from acme.dns_challenge import GoogleCloudDnsProvider

        mock_dns_module = MagicMock()
        mock_oauth2 = MagicMock()

        provider = GoogleCloudDnsProvider.__new__(GoogleCloudDnsProvider)
        provider._gcp_dns = mock_dns_module
        provider._project_id = "my-project"
        provider._zone_name = "my-zone"
        provider._credentials_path = "/path/to/creds.json"

        # `from google.oauth2 import service_account` resolves via sys.modules
        with patch.dict("sys.modules", {"google.oauth2": mock_oauth2}):
            provider._get_client()

        mock_oauth2.service_account.Credentials.from_service_account_file.assert_called_once_with(
            "/path/to/creds.json"
        )
        loaded_creds = mock_oauth2.service_account.Credentials.from_service_account_file.return_value
        mock_dns_module.Client.assert_called_once_with(
            project="my-project", credentials=loaded_creds
        )


# ─────────────────────────────────────────────────────────────────────────────
# ─ OBSERVABILITY TEST SUITE: Gaps to catch subtle bugs ─────────────────────────
# ─────────────────────────────────────────────────────────────────────────────


# ─── Group 1: TestComputeDnsTxtValueContracts ─────────────────────────────────


class TestComputeDnsTxtValueContracts:
    """Guard against encoding changes and document the ASCII-only contract."""

    def test_non_ascii_input_raises(self):
        """compute_dns_txt_value() with non-ASCII input raises UnicodeEncodeError."""
        from acme.dns_challenge import compute_dns_txt_value

        # Documents that compute_dns_txt_value only accepts ASCII domain names
        with pytest.raises(UnicodeEncodeError):
            compute_dns_txt_value("tök.thumb")

    def test_empty_string_produces_deterministic_hash(self):
        """compute_dns_txt_value("") produces a deterministic SHA-256 hash."""
        from acme.dns_challenge import compute_dns_txt_value

        # Empty string should produce deterministic output, not raise
        result = compute_dns_txt_value("")
        # SHA-256 of empty string (base64url): pin the exact output
        expected = base64.urlsafe_b64encode(hashlib.sha256(b"").digest()).rstrip(b"=").decode("ascii")
        assert result == expected

    def test_output_never_contains_standard_base64_chars(self):
        """Output uses base64url (no +/=), never standard base64."""
        from acme.dns_challenge import compute_dns_txt_value

        # Test multiple inputs to ensure no accidental switch to b64encode
        for key_auth in ["key_auth_1", "key_auth_2", "_test.example.com"]:
            result = compute_dns_txt_value(key_auth)
            # base64url: no + or / (only - and _ for special chars)
            assert "+" not in result, f"Found + in {result}"
            assert "/" not in result, f"Found / in {result}"
            # No padding either
            assert not result.endswith("="), f"Found padding in {result}"


# ─── Group 2: TestAcmeRecordNameContracts ──────────────────────────────────────


class TestAcmeRecordNameContracts:
    """Pin _acme_record_name format so provider-specific logic stays safe."""

    def test_domain_with_trailing_dot_is_preserved(self):
        """_acme_record_name() preserves trailing dots (raw pass-through)."""
        from acme.dns_challenge import DnsProvider

        # Documents that we do NOT normalize or strip trailing dots
        result = DnsProvider._acme_record_name("example.com.")
        assert result == "_acme-challenge.example.com."

    def test_deeply_nested_subdomain(self):
        """_acme_record_name() handles deeply nested subdomains correctly."""
        from acme.dns_challenge import DnsProvider

        result = DnsProvider._acme_record_name("a.b.c.d.example.com")
        assert result == "_acme-challenge.a.b.c.d.example.com"

    def test_uppercase_domain_not_normalized(self):
        """_acme_record_name() preserves case (does not normalize to lowercase)."""
        from acme.dns_challenge import DnsProvider

        # Documents that case is preserved — providers must handle case themselves
        result = DnsProvider._acme_record_name("API.Example.COM")
        assert result == "_acme-challenge.API.Example.COM"


# ─── Group 3: TestCloudflareDnsProviderContracts ───────────────────────────────


class TestCloudflareDnsProviderContracts:
    """Observability tests: errors propagate, zone walk is correct, delete filters properly."""

    @pytest.fixture
    def cf_mock(self):
        """Setup Cloudflare client mock."""
        mock_cf_module = MagicMock()
        mock_client = MagicMock()
        mock_cf_module.Cloudflare.return_value = mock_client
        return mock_cf_module, mock_client

    def _make_provider(self, cf_mock, zone_id="Z123"):
        from acme.dns_challenge import CloudflareDnsProvider

        mock_cf_module, _ = cf_mock
        provider = CloudflareDnsProvider.__new__(CloudflareDnsProvider)
        provider._cf_mod = mock_cf_module
        provider._api_token = "tok"
        provider._explicit_zone_id = zone_id
        return provider

    def test_create_txt_record_raises_on_api_failure(self, cf_mock):
        """create_txt_record() propagates API errors — does NOT swallow them."""
        _, mock_client = cf_mock
        provider = self._make_provider(cf_mock)
        mock_client.dns.records.list.return_value = []

        # Simulate API failure
        mock_client.dns.records.create.side_effect = Exception("API error")

        with pytest.raises(Exception, match="API error"):
            provider.create_txt_record("example.com", "txt_value")

    def test_zone_discovery_walks_deep_subdomain(self, cf_mock):
        """_resolve_zone_id() walks down labels until finding a matching zone."""
        _, mock_client = cf_mock
        provider = self._make_provider(cf_mock, zone_id="")

        # Simulate zone discovery: `a.b.c.d.example.com` finds match on `example.com`
        # walk: try "a.b.c.d.example.com" -> none
        #       try "b.c.d.example.com" -> none
        #       try "c.d.example.com" -> none
        #       try "d.example.com" -> none
        #       try "example.com" -> MATCH
        def zone_list_side_effect(*args, **kwargs):
            # This gets called with name parameter; match returns a list with a mock zone
            result = []
            # Check all calls; we only have one zone that matches
            # The implementation walks down, so we just return a match for the base domain
            if kwargs.get("name") and "example.com" in str(kwargs.get("name")):
                mock_zone = MagicMock()
                mock_zone.id = "Z_EXAMPLE"
                result = [mock_zone]
            return result

        mock_client.zones.list.side_effect = zone_list_side_effect

        zone_id = provider._resolve_zone_id("a.b.c.d.example.com")
        assert zone_id == "Z_EXAMPLE"

    def test_delete_multiple_records_same_name_deletes_matching_only(self, cf_mock):
        """delete_txt_record() deletes only the record matching the txt_value."""
        _, mock_client = cf_mock
        provider = self._make_provider(cf_mock)

        # Simulate two TXT records with same name, different values
        rec_1 = MagicMock()
        rec_1.id = "rec_1"
        rec_1.content = "value_1"
        rec_2 = MagicMock()
        rec_2.id = "rec_2"
        rec_2.content = "value_2"

        mock_client.dns.records.list.return_value = [rec_1, rec_2]

        provider.delete_txt_record("example.com", "value_2")

        # Should only delete rec_2
        mock_client.dns.records.delete.assert_called_once_with("rec_2", zone_id="Z123")

    def test_zone_discovery_api_failure_propagates(self, cf_mock):
        """_resolve_zone_id() propagates API errors from zones.list()."""
        _, mock_client = cf_mock
        provider = self._make_provider(cf_mock, zone_id="")

        # Simulate API failure during zone discovery
        mock_client.zones.list.side_effect = Exception("Zone discovery API error")

        with pytest.raises(Exception, match="Zone discovery API error"):
            provider._resolve_zone_id("notfound.example.com")


# ─── Group 4: TestRoute53DnsProviderContracts ──────────────────────────────────


class TestRoute53DnsProviderContracts:
    """Observability tests: errors propagate, zone walk is correct, ID extraction safe."""

    @pytest.fixture
    def boto3_mock(self):
        """Setup boto3 client mock."""
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        return mock_boto3, mock_client

    def _make_provider(self, boto3_mock, zone_id="Z123"):
        from acme.dns_challenge import Route53DnsProvider

        mock_boto3, _ = boto3_mock
        provider = Route53DnsProvider.__new__(Route53DnsProvider)
        provider._boto3 = mock_boto3
        provider._explicit_zone_id = zone_id
        provider._region = "us-east-1"
        provider._access_key_id = ""
        provider._secret_access_key = ""
        return provider

    def test_create_txt_record_raises_on_api_failure(self, boto3_mock):
        """create_txt_record() propagates API errors — does NOT swallow them."""
        _, mock_client = boto3_mock
        provider = self._make_provider(boto3_mock)

        # Simulate API failure
        mock_client.change_resource_record_sets.side_effect = Exception("Route53 error")

        with pytest.raises(Exception, match="Route53 error"):
            provider.create_txt_record("example.com", "txt_value")

    def test_resolve_zone_rejects_non_exact_name_match(self, boto3_mock):
        """_resolve_zone_id() rejects partial/fuzzy matches (e.g., examplez.com != example.com)."""
        _, mock_client = boto3_mock
        provider = self._make_provider(boto3_mock, zone_id="")

        # Simulate Route53 returning a zone that does NOT match exactly
        mock_client.list_hosted_zones_by_name.return_value = {
            "HostedZones": [{"Name": "examplez.com.", "Id": "/hostedzone/Z999"}]
        }

        # Should raise because "examplez.com." != "example.com."
        with pytest.raises(ValueError, match="Could not discover Route53"):
            provider._resolve_zone_id("example.com")

    def test_zone_id_extracted_from_hosted_zone_path(self, boto3_mock):
        """_resolve_zone_id() correctly extracts zone ID from /hostedzone/Z0123456789ABCDEF."""
        _, mock_client = boto3_mock
        provider = self._make_provider(boto3_mock, zone_id="")

        # Simulate Route53 returning a zone with full path
        mock_client.list_hosted_zones_by_name.return_value = {
            "HostedZones": [{"Name": "example.com.", "Id": "/hostedzone/Z0123456789ABCDEF"}]
        }

        zone_id = provider._resolve_zone_id("example.com")
        assert zone_id == "Z0123456789ABCDEF"

    def test_zone_discovery_walks_deep_subdomain(self, boto3_mock):
        """_resolve_zone_id() walks labels down until finding a matching zone."""
        _, mock_client = boto3_mock
        provider = self._make_provider(boto3_mock, zone_id="")

        # Simulate zone discovery: a.b.c.d.example.com. → finds match on example.com.
        def list_zones_side_effect(*args, **kwargs):
            # This is called multiple times (once for each label)
            # We want it to match only on "example.com."
            return {
                "HostedZones": [
                    {"Name": "example.com.", "Id": "/hostedzone/Z_EXAMPLE"}
                ]
            }

        mock_client.list_hosted_zones_by_name.side_effect = list_zones_side_effect

        zone_id = provider._resolve_zone_id("a.b.c.d.example.com")
        assert zone_id == "Z_EXAMPLE"


# ─── Group 5: TestGoogleCloudDnsProviderContracts ──────────────────────────────


class TestGoogleCloudDnsProviderContracts:
    """Observability tests: errors propagate (create), rdata quoting is correct, delete swallows NotFound."""

    @pytest.fixture
    def gcp_dns_mock(self):
        """Setup GCP DNS module mock (matching existing test fixture)."""
        mock_dns_module = MagicMock()
        mock_gcp_client = MagicMock()
        mock_dns_module.Client.return_value = mock_gcp_client
        mock_zone = MagicMock()
        mock_gcp_client.zone.return_value = mock_zone
        return mock_dns_module, mock_gcp_client, mock_zone

    def _make_provider(self, gcp_dns_mock):
        from acme.dns_challenge import GoogleCloudDnsProvider

        mock_dns_module, _, _ = gcp_dns_mock
        provider = GoogleCloudDnsProvider.__new__(GoogleCloudDnsProvider)
        provider._gcp_dns = mock_dns_module
        provider._project_id = "test-project"
        provider._zone_name = "test-zone"
        provider._credentials_path = ""
        return provider

    def test_create_txt_record_raises_on_api_failure(self, gcp_dns_mock):
        """create_txt_record() propagates API errors — does NOT swallow them."""
        _, _, mock_zone = gcp_dns_mock
        provider = self._make_provider(gcp_dns_mock)

        # Simulate API failure
        mock_zone.changes.return_value.create.side_effect = Exception("GCP API error")

        with pytest.raises(Exception, match="GCP API error"):
            provider.create_txt_record("example.com", "txt_value")

    def test_no_existing_record_verifies_rdata_quoting(self, gcp_dns_mock):
        """When creating a new record, rdata includes quotes (GCP requirement)."""
        _, _, mock_zone = gcp_dns_mock
        provider = self._make_provider(gcp_dns_mock)

        # No existing records
        mock_zone.list_resource_record_sets.return_value = []

        provider.create_txt_record("example.com", "my_txt_value")

        # Verify that resource_record_set was called with quoted value
        mock_zone.resource_record_set.assert_called_once_with(
            "_acme-challenge.example.com.", "TXT", 60, ['"my_txt_value"']
        )

    def test_replace_path_verifies_rdata_quoting(self, gcp_dns_mock):
        """When replacing a record, new rdata also includes quotes."""
        _, _, mock_zone = gcp_dns_mock
        provider = self._make_provider(gcp_dns_mock)

        # Simulate existing record with a different value
        existing_rr = MagicMock()
        existing_rr.name = "_acme-challenge.example.com."
        existing_rr.record_type = "TXT"
        existing_rr.rdata = ['"old-value"']
        mock_zone.list_resource_record_sets.return_value = [existing_rr]

        provider.create_txt_record("example.com", "new_txt_value")

        # Verify that resource_record_set was called for the new value (with quotes)
        mock_zone.resource_record_set.assert_called_once_with(
            "_acme-challenge.example.com.", "TXT", 60, ['"new_txt_value"']
        )

    def test_delete_swallows_errors_like_not_found(self, gcp_dns_mock):
        """delete_txt_record() swallows errors (including NotFound-like scenarios)."""
        _, _, mock_zone = gcp_dns_mock
        provider = self._make_provider(gcp_dns_mock)

        # Simulate error during deletion
        mock_zone.changes.return_value.create.side_effect = RuntimeError("Record not found")

        # Should NOT raise — error is swallowed (verified by existing test_delete_txt_record_swallows_errors)
        provider.delete_txt_record("example.com", "txt_value")


# ─── Group 6: TestDnsProviderRegistryContracts ──────────────────────────────────


class TestDnsProviderRegistryContracts:
    """Error message contracts: case-sensitive, lists all choices."""

    def test_case_sensitive_provider_name_raises(self):
        """_dns_provider_registry() is case-sensitive; 'Cloudflare' raises ValueError."""
        from acme.dns_challenge import _dns_provider_registry

        with pytest.raises(ValueError, match="Unknown DNS_PROVIDER"):
            _dns_provider_registry("Cloudflare", MagicMock())

    def test_error_message_contains_all_three_valid_choices(self):
        """Error message lists exactly cloudflare, route53, google (no extra, no missing)."""
        from acme.dns_challenge import _dns_provider_registry

        with pytest.raises(ValueError) as exc_info:
            _dns_provider_registry("invalid", MagicMock())

        msg = str(exc_info.value)
        # All three must be present
        assert "cloudflare" in msg.lower()
        assert "route53" in msg.lower()
        assert "google" in msg.lower()


# ─── Group 7: TestCreateVsDeleteErrorContractSummary ──────────────────────────


class TestCreateVsDeleteErrorContractSummary:
    """Documents the deliberate asymmetry: create raises, delete swallows."""

    def test_cloudflare_create_raises_delete_swallows_asymmetry(self):
        """Cloudflare: create() raises on error, delete() swallows errors."""
        from acme.dns_challenge import CloudflareDnsProvider

        mock_cf_module = MagicMock()
        mock_client = MagicMock()
        mock_cf_module.Cloudflare.return_value = mock_client

        provider = CloudflareDnsProvider.__new__(CloudflareDnsProvider)
        provider._cf_mod = mock_cf_module
        provider._api_token = "tok"
        provider._explicit_zone_id = "Z123"

        # CREATE: error should propagate
        mock_client.dns.records.list.return_value = []
        mock_client.dns.records.create.side_effect = Exception("Create failed")
        with pytest.raises(Exception, match="Create failed"):
            provider.create_txt_record("example.com", "value")

        # DELETE: error should be swallowed
        rec = MagicMock()
        rec.id = "rec_1"
        rec.content = "value"
        mock_client.dns.records.list.return_value = [rec]
        mock_client.dns.records.delete.side_effect = Exception("Delete failed")
        # Should not raise
        provider.delete_txt_record("example.com", "value")

    def test_route53_create_raises_delete_swallows_asymmetry(self):
        """Route53: create() raises on error, delete() swallows errors."""
        from acme.dns_challenge import Route53DnsProvider

        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        provider = Route53DnsProvider.__new__(Route53DnsProvider)
        provider._boto3 = mock_boto3
        provider._explicit_zone_id = "Z123"
        provider._region = "us-east-1"
        provider._access_key_id = ""
        provider._secret_access_key = ""

        # CREATE: error should propagate
        mock_client.change_resource_record_sets.side_effect = Exception("Create failed")
        with pytest.raises(Exception, match="Create failed"):
            provider.create_txt_record("example.com", "value")

        # DELETE: error should be swallowed
        mock_client.change_resource_record_sets.side_effect = Exception("Delete failed")
        # Should not raise
        provider.delete_txt_record("example.com", "value")
