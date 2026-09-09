# CA Providers — Selection and Setup

Use this page to choose and configure your ACME Certificate Authority.

## When to use this page

- "Which CA should I use?"
- "How do I set up DigiCert / ZeroSSL / Sectigo?"
- "What is EAB and do I need it?"
- "Can I use a custom ACME endpoint?"

## Canonicality

- **Canonical for**: CA provider selection, EAB configuration, custom ACME endpoints
- **Not canonical for**: General configuration (→ [CONFIGURATION.md](CONFIGURATION.md)), Let's Encrypt specifics (→ [LETS_ENCRYPT.md](LETS_ENCRYPT.md)), ACME protocol details (→ [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md))

---

## Quick Selection Guide

| CA | Requires EAB | Cost | Use When | Config |
|---|---|---|---|---|
| **Let's Encrypt** | No | Free | Public internet, free certificates, testing | `CA_PROVIDER=letsencrypt` |
| **Let's Encrypt Staging** | No | Free | Testing (doesn't count against rate limits) | `CA_PROVIDER=letsencrypt_staging` |
| **DigiCert** | Yes | Paid | Enterprise, high-trust certs | `CA_PROVIDER=digicert` |
| **ZeroSSL** | Yes | Mixed | Alternative EAB provider, free tier available | `CA_PROVIDER=zerossl` |
| **Sectigo** | Yes | Paid | Legacy/compatibility | `CA_PROVIDER=sectigo` |
| **Custom** | Varies | Varies | Non-standard ACME endpoints | `CA_PROVIDER=custom` + `ACME_DIRECTORY_URL` |

---

## Let's Encrypt

### Production Endpoint

- **Directory URL**: `https://acme-v02.api.letsencrypt.org/directory`
- **Rate limits**: 50 certificates per domain per week (generous)
- **Cost**: Free
- **Setup**: No API credentials needed — registration happens via email validation

### Staging Endpoint

- **Directory URL**: `https://acme-staging-v02.api.letsencrypt.org/directory`
- **Use for**: Development and testing before production
- **Rate limits**: Much higher than production (for testing)
- **Certificate trust**: Certificates are **not** trusted by browsers (staging CA is self-signed)
- **Setup**: Same as production, just change `CA_PROVIDER`

### Configuration

```bash
# Production
export CA_PROVIDER=letsencrypt
export ACME_INSECURE=false  # optional; defaults to false

# Staging
export CA_PROVIDER=letsencrypt_staging
export ACME_INSECURE=false  # optional; defaults to false
```

**See also**: [LETS_ENCRYPT.md](LETS_ENCRYPT.md) for Let's Encrypt-specific details.

---

## DigiCert (EAB Required)

### Endpoint

- **Directory URL**: `https://acme.digicert.com/v2/DV/directory` (Domain Validated certs)
- **Other types**: OV (`/v2/OV/directory`), EV (`/v2/EV/directory`) — requires agent changes
- **Cost**: Contact DigiCert for pricing
- **Rate limits**: Typically 100+ per domain/week (check with DigiCert)

### External Account Binding (EAB)

DigiCert requires **EAB** — a signing credential issued by DigiCert that proves you control the account.

1. **Obtain EAB credentials from DigiCert**:
   - Log into your DigiCert account
   - Navigate to API → ACME → Create new API token
   - Copy the **Key ID** and **HMAC Key**

2. **Configure environment variables**:

```bash
export CA_PROVIDER=digicert
export ACME_EAB_KEY_ID=your_digicert_key_id
export ACME_EAB_HMAC_KEY=your_digicert_hmac_key
export ACME_INSECURE=false
```

3. **Test configuration**:

```bash
python main.py --once --domains test.example.com
```

### See also

- RFC 8555 §7.3.4 (EAB): [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)
- ACME client implementation: [acme/client.py](../acme/client.py) (class `DigiCertAcmeClient`)

---

## ZeroSSL (EAB Required)

### Endpoint

- **Directory URL**: `https://acme.zerossl.com/v2/DV90/directory`
- **Cost**: Free tier available (limited certs/month); paid tiers available
- **Rate limits**: Check ZeroSSL account dashboard

### External Account Binding (EAB)

1. **Obtain EAB credentials from ZeroSSL**:
   - Log into your ZeroSSL account
   - Navigate to API Console → ACME credentials
   - Copy the **Key ID** and **HMAC Key**

2. **Configure environment variables**:

```bash
export CA_PROVIDER=zerossl
export ACME_EAB_KEY_ID=your_zerossl_key_id
export ACME_EAB_HMAC_KEY=your_zerossl_hmac_key
export ACME_INSECURE=false
```

3. **Test configuration**:

```bash
python main.py --once --domains test.example.com
```

### See also

- ACME client implementation: [acme/client.py](../acme/client.py) (class `ZeroSSLAcmeClient`)

---

## Sectigo (EAB Required)

### Endpoint

- **Directory URL**: `https://acme.sectigo.com/v2/DV/directory`
- **Cost**: Paid
- **Rate limits**: Check your Sectigo account

### External Account Binding (EAB)

1. **Obtain EAB credentials from Sectigo**:
   - Log into your Sectigo account
   - Navigate to API → ACME credentials
   - Copy the **Key ID** and **HMAC Key**

2. **Configure environment variables**:

```bash
export CA_PROVIDER=sectigo
export ACME_EAB_KEY_ID=your_sectigo_key_id
export ACME_EAB_HMAC_KEY=your_sectigo_hmac_key
export ACME_INSECURE=false
```

3. **Test configuration**:

```bash
python main.py --once --domains test.example.com
```

### See also

- ACME client implementation: [acme/client.py](../acme/client.py) (class `SectigoAcmeClient`)

---

## Custom ACME Endpoint

### Use Case

- You have a non-standard ACME server (e.g., custom internal CA, Pebble for testing)
- You want to manually specify the directory URL

### Configuration

```bash
export CA_PROVIDER=custom
export ACME_DIRECTORY_URL=https://your-ca.example.com/acme/directory
export ACME_INSECURE=false  # set to 'true' ONLY for testing with self-signed certs
```

### CA Detection

When using a custom endpoint, the agent will attempt to **detect which CA issued existing certificates** by inspecting the X.509 issuer O field. If a known CA is detected, a warning is logged:

```
WARNING: Existing cert was issued by 'letsencrypt' but CA_PROVIDER=custom
         Consider setting CA_PROVIDER=letsencrypt
```

This detection is **advisory only** — the configured `CA_PROVIDER=custom` always governs renewal.

**See**: [acme/ca_detection.py](../acme/ca_detection.py) for implementation.

---

## Switching CAs

### Safe Migration

1. **Make a backup of your current certs** (if important):
   ```bash
   cp -r certs/ certs.backup/
   ```

2. **Update `CA_PROVIDER`**:
   ```bash
   export CA_PROVIDER=new_provider
   export ACME_EAB_KEY_ID=...  # if needed
   export ACME_EAB_HMAC_KEY=... # if needed
   ```

3. **Test with a single domain**:
   ```bash
   python main.py --once --domains test.example.com
   ```

4. **If successful, run renewal for all domains**:
   ```bash
   python main.py --once
   ```

### What Happens to Old Certs

- Old certificates (issued by the previous CA) remain on disk
- New renewals use the new CA
- No automatic cleanup or revocation of old certs
- If desired, manually revoke old certs:
  ```bash
  export CA_PROVIDER=old_provider  # temporarily switch back
  python main.py --revoke-cert example.com
  ```

---

## Troubleshooting

### "badNonce" or "urn:acme:error:accountDoesNotExist"

- **Cause**: Invalid EAB credentials or wrong CA endpoint
- **Fix**: Verify `ACME_EAB_KEY_ID` and `ACME_EAB_HMAC_KEY` from your CA dashboard
- **Test**: `python main.py --once --domains test.example.com`

### "DNS name mismatch" or TLS errors

- **Cause**: `ACME_INSECURE=false` but CA has a self-signed cert (e.g., Pebble testing)
- **Fix**: Set `ACME_INSECURE=true` for testing only; never in production
- **See**: [SECURITY.md](SECURITY.md#3-tls-enforcement-for-acme-api-calls)

### Rate limit errors

- **Cause**: Hit CA's certificate issuance limit
- **Fix**: Wait (limits reset daily/weekly depending on CA), or switch to staging for testing
- **Check**: Your CA's rate limit documentation

---

## See also

- Quick start: [SETUP.md](SETUP.md)
- Full configuration: [CONFIGURATION.md](CONFIGURATION.md)
- Feature matrix: [FEATURE_MATRIX.md](FEATURE_MATRIX.md)
- Let's Encrypt specifics: [LETS_ENCRYPT.md](LETS_ENCRYPT.md)
- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- RFC compliance: [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)
