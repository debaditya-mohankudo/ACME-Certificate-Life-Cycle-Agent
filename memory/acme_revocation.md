---
name: acme-revocation
description: Certificate revocation is a separate LangGraph — CLI flag, reason codes, and key behaviour
metadata:
  type: project
  domain: acme
  priority: 20
  tags: revocation, langgraph, revoker, reason-codes, cli
---

Revocation runs as a **separate LangGraph** defined in `agent/revocation_graph.py` — it does not share the renewal graph.

**CLI:**
```bash
python main.py --revoke-cert example.com
python main.py --revoke-cert example.com api.example.com --reason 4
```

**Reason codes (RFC 8555 / RFC 5280 §5.3.1):** 0=unspecified, 1=keyCompromise, 2=cACompromise, 3=affiliationChanged, 4=superseded, 5=cessationOfOperation. Only 0–10 are valid; anything else raises `ValueError` before any ACME call.

**Key nodes:** `revoker` (`agent/nodes/revoker.py`) — loads cert PEM from disk, POSTs to ACME `revokeCert` endpoint, deletes cert files via storage layer.
Routing: `revocation_router` decides success vs error path.

**How to apply:** Any change to revocation flow must update `agent/revocation_graph.py` and `doc/REVOCATION_IMPLEMENTATION.md`. Reason code validation is in `acme/client.py` — do not duplicate it in the node.
