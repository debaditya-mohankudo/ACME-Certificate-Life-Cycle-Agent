# RFC 8555 (ACME) protocol graph

Ontology-driven reference graph for the **core certificate-issuance flow** of the ACME protocol, in PKI / certificate-management domain language. Source: RFC 8555 (<https://www.rfc-editor.org/info/rfc8555/>), plus RFC 8737 for `tls-alpn-01`.

This maps the protocol **as specified**. For how *this repo* implements it see [`RFC_COMPLIANCE.md`](./RFC_COMPLIANCE.md); for the codebase's ubiquitous language see [`../ontology/acme-cert-lifecycle-domain.json`](../ontology/acme-cert-lifecycle-domain.json).

Machine-readable form: [`RFC8555_ACME_PROTOCOL_GRAPH.json`](./RFC8555_ACME_PROTOCOL_GRAPH.json) (`meta` / `relation_types` / `nodes` / `edges`; `edges` is the binary projection of the hyperedges below, grouped by `hyperedge_id`).

---

Nodes are atomic protocol facts; hyperedges are typed, possibly n-ary relationships
over a closed vocabulary. **In scope:** the happy-path issuance flow plus the order /
authorization / challenge state machines. **Out of scope:** account key rollover,
deactivation, pre-authorization (`newAuthz`), revocation, external account binding,
the full error taxonomy.

## Nodes

### Actors
- **The ACME client acts for the certificate applicant and holds the account key pair; it originates every protocol request** — _actor_ — RFC 8555 §1.2 `acme_client`
- **The ACME server is the CA; it issues nonces, registers accounts, creates authorizations, runs validation, and issues certificates** — _actor_ — RFC 8555 §1.2 `acme_ca`

### Resources
- **The directory is the ACME entry point; a GET returns the URLs for newNonce, newAccount, newOrder, newAuthz, revokeCert, keyChange, plus a meta object** — _resource_ — RFC 8555 §7.1.1 `directory_resource`
- **An account object represents the client's registration and binds the account public key to a status, a contact list, and the termsOfServiceAgreed flag** — _resource_ — RFC 8555 §7.1.2 `account_resource`
- **An order object represents one certificate request, carrying identifiers, authorization URLs, a finalize URL, an expires timestamp, a status, and (once issued) a certificate URL** — _resource_ — RFC 8555 §7.1.3 `order_resource`
- **An authorization object is the CA's per-identifier grant to an account; it holds the identifier, a challenges list, a status, and (when valid) a required expires timestamp** — _resource_ — RFC 8555 §7.1.4 `authorization_resource`
- **A challenge object is one offered proof-of-control method inside an authorization, carrying type, token, url, and status** — _resource_ — RFC 8555 §7.1.5 `challenge_resource`
- **The certificate resource is the issued PEM certificate chain, fetched by POST-as-GET from the order's certificate URL** — _resource_ — RFC 8555 §7.4.2 `certificate_resource`
- **A replay nonce is a single-use server value delivered in the Replay-Nonce header and obtained from newNonce; responses carrying it are marked no-store** — _credential_ — RFC 8555 §7.2 `replay_nonce`

### Credentials & signed artifacts
- **The account key pair is generated client-side; its public key is registered on the account and its private key signs every subsequent request** — _credential_ — RFC 8555 §6.2 `account_key_pair`
- **Every ACME POST body is a JWS whose protected header carries alg, nonce, url, and exactly one of jwk or kid** — _credential_ — RFC 8555 §6.2 `jws_request`
- **newAccount and revokeCert carry the full public key in the jwk header; every other request carries kid = the account URL** — _credential_ — RFC 8555 §6.2 `jwk_vs_kid`
- **Order finalization submits a base64url PKCS#10 CSR whose requested names must match the order's identifiers** — _credential_ — RFC 8555 §7.4 `csr_object`
- **The key authorization is token + "." + base64url(SHA-256(account-key JWK thumbprint)), binding a challenge token to the account key** — _proof_ — RFC 8555 §8.1 `key_authorization`

### Identifier
- **An identifier is a {type:"dns", value:<domain>} pair naming a name to be certified; wildcard authorizations set wildcard:true** — _identifier_ — RFC 8555 §7.1.4 `dns_identifier`

### Proof-of-control methods
- **http-01: the client serves the key authorization as the body of http://&lt;domain&gt;/.well-known/acme-challenge/&lt;token&gt;** — _proof_ — RFC 8555 §8.3 `http_01`
- **dns-01: the client publishes a TXT record at _acme-challenge.&lt;domain&gt; whose value is base64url(SHA-256(key authorization)); the only method valid for wildcards** — _proof_ — RFC 8555 §8.4 `dns_01`
- **tls-alpn-01: the client serves a self-signed certificate carrying the key-authorization digest via the acme-tls/1 ALPN protocol on port 443** — _proof_ — RFC 8737 §3 `tls_alpn_01`

### Operations
- **newNonce: a HEAD or GET that returns a fresh Replay-Nonce and nothing else** — _operation_ — RFC 8555 §7.2 `new_nonce_op`
- **newAccount: a jwk-signed POST with contact and termsOfServiceAgreed; a 201 returns the account URL in the Location header** — _operation_ — RFC 8555 §7.3 `new_account_op`
- **newOrder: a POST of the identifiers list; a 201 returns a pending order with its authorization URLs and finalize URL** — _operation_ — RFC 8555 §7.4 `new_order_op`
- **The client POST-as-GETs each authorization URL to read its challenge list and pick one method** — _operation_ — RFC 8555 §7.5 `fetch_authz_op`
- **The client POSTs an empty object to the chosen challenge URL to signal the proof is provisioned and validation may start** — _operation_ — RFC 8555 §7.5.1 `respond_challenge_op`
- **On challenge response the CA connects to the identifier (HTTP path, DNS TXT, or TLS-ALPN) and compares the retrieved artifact to the expected key authorization, with retries** — _operation_ — RFC 8555 §8.2 `validation_check`
- **Once the order is ready the client POSTs the CSR to the order's finalize URL** — _operation_ — RFC 8555 §7.4 `finalize_op`
- **The client POST-as-GETs the order's certificate URL to download the PEM chain** — _operation_ — RFC 8555 §7.4.2 `download_cert_op`

### Constraints
- **Each nonce is single-use; a stale or unknown nonce is rejected with badNonce and a fresh nonce is supplied for retry** — _constraint_ — RFC 8555 §6.5 `nonce_antireplay`
- **The JWS protected "url" header must equal the HTTP request URL, binding the signature to one endpoint** — _constraint_ — RFC 8555 §6.4 `url_binding`
- **When the directory meta requires it, newAccount without termsOfServiceAgreed:true does not create an account** — _constraint_ — RFC 8555 §7.3.1 `tos_agreement`
- **The order's expires timestamp bounds its lifetime; past it the order is invalid** — _constraint_ — RFC 8555 §7.1.3 `order_expiry`
- **Reads of account-bound resources use POST-as-GET — a signed JWS with an empty ("") payload — not an anonymous GET** — _constraint_ — RFC 8555 §6.3 `post_as_get`

### Order state machine
- **Order status "pending": at least one of the order's authorizations is not yet valid** — _state_ — RFC 8555 §7.1.6 `order_pending`
- **Order status "ready": every authorization is valid and the client may finalize** — _state_ — RFC 8555 §7.1.6 `order_ready`
- **Order status "processing": the CA is issuing from the submitted CSR** — _state_ — RFC 8555 §7.1.6 `order_processing`
- **Order status "valid": the certificate is issued and the order's certificate URL is populated** — _state_ — RFC 8555 §7.1.6 `order_valid`
- **Order status "invalid": an authorization failure/expiry, a processing error, or order expiry has terminated the order** — _state_ — RFC 8555 §7.1.6 `order_invalid`

### Authorization state machine
- **Authorization status "pending": no challenge has yet succeeded** — _state_ — RFC 8555 §7.1.6 `authz_pending`
- **Authorization status "valid": one challenge succeeded; an expires timestamp is now required** — _state_ — RFC 8555 §7.1.6 `authz_valid`
- **Authorization status "invalid": a challenge failed or an error occurred** — _state_ — RFC 8555 §7.1.6 `authz_invalid`
- **A valid authorization can later move to "deactivated" (client request), "expired" (expires passes), or "revoked" (server)** — _state_ — RFC 8555 §7.1.6 `authz_terminal_other`

### Challenge state machine
- **Challenge status "pending": the client has not yet responded** — _state_ — RFC 8555 §7.1.6 `challenge_pending`
- **Challenge status "processing": the CA is attempting validation and may retry** — _state_ — RFC 8555 §7.1.6 `challenge_processing`
- **Challenge status "valid": the CA confirmed the proof and set the validated timestamp** — _state_ — RFC 8555 §7.1.6 `challenge_valid`
- **Challenge status "invalid": validation failed after the CA's retries** — _state_ — RFC 8555 §7.1.6 `challenge_invalid`

## Hyperedges

- **precedes** — `directory_resource`, `new_nonce_op`, `new_account_op`, `new_order_op`, `fetch_authz_op`, `respond_challenge_op`, `validation_check`, `finalize_op`, `download_cert_op` — canonical ACME issuance sequence from directory to certificate download — RFC 8555 §7.1
- **determines** — `directory_resource`, `new_nonce_op`, `new_account_op`, `new_order_op` — the directory's fields supply the URL each operation targets — RFC 8555 §7.1.1
- **part_of** — `challenge_resource`, `authorization_resource`, `order_resource` — challenges nest in an authorization; authorizations nest by URL in an order — RFC 8555 §7.1.3, §7.1.4
- **determines** — `dns_identifier`, `new_order_op`, `authorization_resource` — the identifiers submitted to newOrder determine the set of authorizations the CA creates, one per identifier — RFC 8555 §7.4
- **authenticates** (+) — `account_key_pair`, `jws_request`, `acme_ca` — the client signs each JWS with the account private key and the CA verifies it against the registered public key — RFC 8555 §6.2
- **determines** — `jwk_vs_kid`, `new_account_op`, `jws_request` — newAccount carries the full jwk because no account exists yet; every later JWS carries kid = account URL — RFC 8555 §6.2
- **constrains** (-) — `nonce_antireplay`, `replay_nonce`, `jws_request` — every JWS must carry a previously-unused nonce or it is rejected, which blocks replay — RFC 8555 §6.5
- **precedes** — `new_nonce_op`, `jws_request` — a fresh nonce must be obtained before the first signed POST — RFC 8555 §7.2
- **constrains** (-) — `url_binding`, `jws_request` — the protected "url" header must equal the request URL, so a captured JWS cannot be replayed against another endpoint — RFC 8555 §6.4
- **constrains** (-) — `tos_agreement`, `new_account_op`, `account_resource` — without termsOfServiceAgreed:true (when the directory requires it) no account is created — RFC 8555 §7.3.1
- **constrains** — `post_as_get`, `fetch_authz_op`, `download_cert_op` — reads of these account-bound resources use a signed empty-payload JWS, not an anonymous GET — RFC 8555 §6.3
- **is_a** — `challenge_resource`, `http_01`, `dns_01`, `tls_alpn_01` — a challenge object's "type" is one of http-01, dns-01, or tls-alpn-01 — RFC 8555 §8, RFC 8737
- **determines** — `challenge_resource`, `account_key_pair`, `key_authorization` — the key authorization is derived from the challenge token and the account-key thumbprint, so a stolen token alone cannot answer the challenge — RFC 8555 §8.1
- **proves_control_of** (+) — `http_01`, `key_authorization`, `dns_identifier` — serving the key authorization at /.well-known/acme-challenge/&lt;token&gt; over HTTP on the domain demonstrates control of the name — RFC 8555 §8.3
- **proves_control_of** (+) — `dns_01`, `key_authorization`, `dns_identifier` — a TXT record at _acme-challenge.&lt;domain&gt; holding SHA-256(key authorization) demonstrates control; this is the method usable for wildcard names — RFC 8555 §8.4
- **proves_control_of** (+) — `tls_alpn_01`, `key_authorization`, `dns_identifier` — a self-signed certificate carrying the key-authorization digest, served via acme-tls/1 ALPN on port 443, demonstrates control — RFC 8737 §3
- **precedes** — `respond_challenge_op`, `validation_check`, `challenge_valid` — posting to the challenge URL triggers the CA's validation attempt, which on success marks the challenge valid — RFC 8555 §7.5.1
- **causes** (+) — `validation_check`, `challenge_valid`, `authz_valid`, `order_ready` — one successful validation propagates up the hierarchy: challenge→valid, its authorization→valid, and once all authorizations are valid the order→ready — RFC 8555 §7.1.6
- **authorizes** (+) — `authz_valid`, `dns_identifier`, `finalize_op` — a valid authorization is the CA's standing permission that this account may be issued certificates for that identifier; finalize consumes it — RFC 8555 §7.1.4
- **precedes** — `order_ready`, `finalize_op` — finalize is only accepted while the order is in "ready" — RFC 8555 §7.4
- **determines** — `csr_object`, `dns_identifier`, `certificate_resource` — the CA issues for exactly the identifiers common to the order and the CSR; a mismatch or weak key is rejected as badCSR — RFC 8555 §7.4
- **precedes** — `finalize_op`, `order_processing`, `order_valid`, `download_cert_op` — after finalize the order moves processing→valid and the client then downloads the chain — RFC 8555 §7.4
- **enables** — `account_resource`, `new_order_op` — only an authenticated account (kid) can create an order — RFC 8555 §7.4
- **transitions_to** — `order_pending`, `order_ready` — trigger: every authorization reaches "valid" — RFC 8555 §7.1.6
- **transitions_to** — `order_ready`, `order_processing` — trigger: client POSTs the CSR to finalize — RFC 8555 §7.1.6
- **transitions_to** — `order_processing`, `order_valid` — trigger: the CA issues the certificate and populates the certificate URL — RFC 8555 §7.1.6
- **transitions_to** — `order_pending`, `order_invalid` — trigger: an authorization becomes invalid or expired, or an error occurs — RFC 8555 §7.1.6
- **transitions_to** — `order_ready`, `order_invalid` — trigger: an error, or the order's "expires" passes before finalize — RFC 8555 §7.1.6
- **transitions_to** — `order_processing`, `order_invalid` — trigger: an error during issuance — RFC 8555 §7.1.6
- **transitions_to** — `authz_pending`, `authz_valid` — trigger: one of its challenges becomes "valid" — RFC 8555 §7.1.6
- **transitions_to** — `authz_pending`, `authz_invalid` — trigger: a challenge fails or an error occurs — RFC 8555 §7.1.6
- **transitions_to** — `authz_valid`, `authz_terminal_other` — trigger: client deactivation, expiry of "expires", or server revocation — RFC 8555 §7.1.6
- **transitions_to** — `challenge_pending`, `challenge_processing` — trigger: client POSTs to the challenge URL — RFC 8555 §7.1.6
- **transitions_to** — `challenge_processing`, `challenge_valid` — trigger: CA validation succeeds and sets "validated" — RFC 8555 §7.1.6
- **transitions_to** — `challenge_processing`, `challenge_invalid` — trigger: CA validation fails after retries — RFC 8555 §7.1.6
- **transitions_to** — `challenge_processing`, `challenge_processing` — trigger: CA retry or client-requested retry — RFC 8555 §7.1.6, §8.2
- **constrains** (-) — `order_expiry`, `order_resource` — the "expires" timestamp caps the order's usable lifetime — RFC 8555 §7.1.3

## Retrieval

To answer a question against this graph: collect the nodes whose claims bear on
the question (the relevant set R), then greedily pick the fewest hyperedges whose
combined nodes cover R. Those edges and their nodes are the answer context; any
R-node no edge covers is a gap in the graph. For "how does a client get a
certificate for example.com" this selects the `precedes` sequence edge plus the
`causes` cascade and the three state-machine transitions on the happy path.

## Graph

The machine-readable graph lives in [`RFC8555_ACME_PROTOCOL_GRAPH.json`](./RFC8555_ACME_PROTOCOL_GRAPH.json).
