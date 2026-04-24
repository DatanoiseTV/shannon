# Observing Claude Code (Anthropic CLI) under shannon

This is a field note from running `claude` (the
`@anthropic-ai/claude-code` CLI) on a box with shannon attached.
What you can and cannot see, and why.

## What shannon shows

Claude Code is a Bun-compiled native binary that ships its own TLS
stack (BoringSSL, statically linked). When you run any subcommand
that touches the network — `claude doctor`, an interactive prompt,
`claude --dangerously-skip-permissions`, etc. — shannon captures:

```
UDP→  pid=… comm="Bun Pool 0"   …:53   ?  A    api.anthropic.com
UDP→  pid=… comm="Bun Pool 0"   …:53   ?  AAAA api.anthropic.com
dns ← rcode=NOERROR  api.anthropic.com -> 160.79.104.10
CONN  pid=… comm="HTTP Client"  …:443  -> 160.79.104.10:443
TCP→  pid=… comm="HTTP Client"  …:443  …
tls → tls ClientHello TLS1.3 sni=api.anthropic.com alpn=http/1.1
tls ← tls ServerHello  TLS1.3 cipher=0x1301
TCP←  …  encrypted application data …
```

That's the **complete** observable set with the standard kernel +
libssl uprobe attach surface. Specifically:

  - DNS queries to `api.anthropic.com` (`shannon trace` prints the
    `dns →` parsed record).
  - The TCP CONN to the resolved Anthropic API IP, with PID +
    `comm` attribution. Claude Code's worker threads show up as
    `Bun Pool N` (DNS) and `HTTP Client` (sockets).
  - The TLS 1.3 ClientHello / ServerHello — full SNI + ALPN + the
    server's chosen cipher suite. shannon's TLS hygiene checker
    runs over the ServerHello; modern Claude Code endpoints pass.
  - Byte counters per direction.

## What shannon doesn't show, and why

**The request body and response body are encrypted and stay
encrypted.** No headers (no `x-api-key`, no `Authorization: Bearer
…`), no JSON payload, no streamed completion bytes. The reason:

  - Claude Code is a single-binary `bun build --compile` artefact
    (`/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe`).
  - BoringSSL is statically linked into that binary with hidden
    symbol visibility. `nm -D` lists only imported glibc symbols;
    even the static `nm` table is stripped of the SSL_* boundary.
  - shannon's libssl uprobes attach to the system
    `/lib/.../libssl.so.3` SSL_read / SSL_write functions. Claude
    Code never calls those — its TLS happens inside `claude.exe`.
  - `shannon trace --attach-bin /usr/local/lib/.../claude.exe`
    will load the BPF programs successfully but the symbol probes
    will silently miss (`ssl_syms=0 sqlite_syms=0`) because the
    target functions aren't exported.

This is the same shape every Bun-bundled or Go-static-TLS binary
produces.

## What you can usefully do anyway

  - **Service map**: `shannon map` will show every flow to
    `api.anthropic.com` with the SNI as the peer label. Useful for
    "how often is this host hitting the API" questions.
  - **Cert pinning**: `shannon trace --dump-certs DIR` then
    `--cert-pin DIR` will catch any unexpected cert chain on the
    Anthropic edge — useful as a MitM canary.
  - **Secret-scanner**: when an `ANTHROPIC_API_KEY` /
    `sk-ant-api03-…` / `sk-ant-oat01-…` (Claude Code subscription
    OAuth) shows up in *any* HTTP body shannon decodes, the
    `secrets.rs` catalogue flags it. The key would have to be
    leaking through some path *other than* `claude.exe`'s TLS for
    shannon to catch it — e.g. a script printing the env.
  - **Outbound classification**: shannon's `llm.rs` already
    recognises `/v1/messages` and `/v1/messages/count_tokens`
    (Claude Code's two main endpoints). Any plaintext flow on
    those paths classifies as Anthropic; that's only useful if
    something *else* is making the requests.

## What it would take to see plaintext

Realistic options, in ascending effort:

  1. Run Claude Code through an MitM proxy you trust
     (`mitmproxy`, Charles, …) with its CA installed. Out of
     scope for shannon.
  2. Wait for Bun to expose `SSLKEYLOGFILE` end-to-end. Some
     Bun versions support the env var for fetch but not for
     bundled-binary builds.
  3. Add a USDT / `bun:tls` probe pair — would need cooperation
     from the Bun runtime upstream.
  4. Reverse-engineer `claude.exe` to find the SSL_read/write
     boundary at fixed offsets and uprobe by address. Brittle;
     ABI changes every Claude Code release.

## Summary

shannon's view of Claude Code is the same view a network passive
observer with TLS unwrapping disabled would have: the *what* (an
Anthropic API call happened, from this PID, with this SNI, this
many bytes) without the *what was said* (request body, response
body, headers).
