---
name: acme-mcp-server
description: MCP server exposes agent operations as tools — how to run it and key tool names
metadata:
  type: project
  domain: acme
  priority: 20
  tags: mcp, tools, server, cli, integration
---

The agent exposes an MCP server (`mcp_server.py`) so Claude Desktop / Claude Code can invoke cert operations as tools.

**Run:**
```bash
uv run python mcp_server.py
```

**Key tools exposed:**
- `list_managed_domains` — returns domains from config
- `health` — agent + CA connectivity check
- `read_cert_details` — parse and return cert metadata for a domain
- `renew_once` — trigger one-shot renewal for specific domains
- `revoke_cert` — revoke a certificate with optional reason code
- `generate_test_cert` — issue a test cert against Let's Encrypt Staging
- `expiring_within` / `expiring_in_30_days` — filter domains by expiry window
- `domain_status` — full status for a single domain

**How to apply:** MCP tools must never introduce side effects beyond what the equivalent CLI flag does. Tool serialization rules are in `doc/MCP_TOOL_SERIALIZATION.md` — all return values must be JSON-serializable primitives (no `datetime`, no `Path`). See `doc/MCP_SERVER.md` for full tool contract.
