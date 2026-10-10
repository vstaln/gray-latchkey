# gray-latchkey

Inject stored credentials into `curl` commands that target configured
hosts. Port of pi's `latchkey` extension.

`tool/before` on `bash` finds every `curl` invocation in the command; when
its segment (up to `;`, `|`, `&`, or newline) mentions a configured host
and doesn't already carry that header, the call is rewritten to
`curl -H '<Header>: <prefix><key>' …` via `decision:"modify"`. `tool/after`
scrubs every known secret value out of the tool result, so the echoed
command and curl's own output show `Bearer [redacted-by-latchkey]` instead
of the key.

## Config

`~/.gray/latchkey/config.json`:

```json
{"hosts": {
  "api.example.com": {"header": "Authorization", "prefix": "Bearer ",
                       "key_env": "EXAMPLE_TOKEN"},
  "internal.lan":    {"header": "X-Api-Key", "key": "literal-not-advised"}
}}
```

- `key_env` — read the secret from this env var at call time (**preferred**)
- `key` — literal secret in the config file (supported, discouraged)
- `header` (default `Authorization`), `prefix` (default `""`)

Hosts are matched as substrings of the curl invocation. Secrets are never
logged or shown — `/latchkey` lists host, header, key source, and
`set`/`MISSING` only.

## Commands

- `/latchkey` — configured hosts and whether each key resolves

## Wire

`plugin/manifest`, `tool/before`, `tool/after`, `command/run`,
`plugin/shutdown`. Protocol 2.0. No state, no capabilities.

## Install

```sh
cargo build --release
gray plugin install ./target/release/gray-latchkey
export EXAMPLE_TOKEN=…   # in gray's environment
```

## Limits

Injection only fires on `bash` calls whose text contains a literal `curl`
token in command position (start, `;`, `|`, `&`, `(`, or after
`sudo`/`env`/`VAR=x`-style prefixes) — `echo curl host` won't touch it.
The segment scan is naive about quoting: a quoted `;|&` can only shrink a
segment and cause a *missed* injection, never a leak to the wrong host.
The secret does pass through the tool args for one hop — redaction in
`tool/after` keeps it out of results, but host-side arg logging is outside
this plugin's reach. Short secrets (< 4 chars) are injected but not
scrubbed.
