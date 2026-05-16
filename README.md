# agbridge

Local TLS MITM bridge that forwards Antigravity / Copilot / Kiro / Cursor traffic to a self-hosted [9router](https://github.com/decolua/9router) VPS. Single static Rust binary, no Node.js on the client.

## Status

> [!WARNING]
> Pre-alpha. The CLI scaffolding compiles but several handlers are stubs.
> Do not use on a machine you depend on for production work yet.

## Why

9router runs everything (provider keys, model aliases, dashboard) on a VPS. To use it from local IDE plugins that have no custom-base-URL setting (Antigravity, Copilot, Kiro, Cursor), you need a local interceptor that:

1. Redirects the IDE's outbound hostnames to `127.0.0.1` via the hosts file.
2. Terminates TLS using a per-host cert signed by a local Root CA.
3. Decodes the request body (Gemini JSON / OpenAI / AWS EventStream / proto).
4. Forwards a normalized payload to the 9router VPS.
5. Re-encodes the streamed response back into the format the IDE expects.

`agbridge` does exactly that.

## Quick start (when implementation lands)

```
cargo install --path crates/agbridge-cli
agbridge config set router_url=https://your-vps.example.com api_key=sk-xxx
sudo agbridge setup     # cert + hosts (admin/sudo)
sudo agbridge start
```

## Security model

- Root CA private key lives at `${DATA_DIR}/cert/rootCA.key` mode `0600`.
- `agbridge` only listens on `127.0.0.1:443` by default, never exposes upstream.
- Outbound traffic only to the configured `router_url`. No telemetry.
- API key passed via env or config file (mode `0600`), never in argv on Unix.
- Logs redact `Authorization`, `Bearer`, and `sk-*` tokens.

See [implementation plan](../brain/.../implementation_plan.md) for full design.

## License

MIT
