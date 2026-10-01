# aigw-claude-code-jwt

Claude Code through a **hybrid** Prisma AIRS / Portkey AI Gateway, authenticated with **short-lived JWTs from your own
identity provider** (IdP) instead of a static gateway key. Claude Code's `apiKeyHelper` runs [`bin/aigw-token`](bin/aigw-token),
which hands Claude Code a valid token and renews it in the middle of a session. Two ways to get the token:

| Path | Who | Grant | Renewal |
|---|---|---|---|
| **Per user** | a developer at a laptop | OAuth device authorization (RFC 8628) with PKCE, one browser sign-in | refresh token, silent |
| **Shared** | a CI runner, a VM, a shared service | OAuth client credentials (client id + secret file) | mint a new token |

> **Disclaimer:** This is a simple, art-of-the-possible example. It is **not** an official Palo Alto Networks, Portkey or
> Anthropic project, it is **not** a recommended or supported production design, and it comes with **no support**. Use it at
> your own risk, under the [MIT License](LICENSE).

```
                  ┌──────────── IdP (OIDC) ────────────┐
                  │ device flow / refresh token        │ JWKS (public keys)
                  │ or client credentials              │
                  ▼                                    ▼
Claude Code ── apiKeyHelper ── bin/aigw-token     AI Gateway (hybrid, JWT_ENABLED=ON) ──► provider (here Vertex AI)
     │          prints a JWT (cached, renewed)         ▲  verifies signature + exp locally,
     └── Authorization: Bearer <JWT>  ─────────────────┘  org/workspace/scopes from claims or gateway settings
         x-portkey-config: <config-slug>
```

The gateway never talks to the IdP for a request. It checks the JWT's signature against the org's JWKS and its `exp`, so a
token is good until it expires. Short tokens (minutes) and a helper that renews them are what make that safe.

Why `apiKeyHelper`: Claude Code reads `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_CUSTOM_HEADERS` once at launch, so a token put
there dies with its `exp`. The helper's output is cached and re-read; Claude Code re-runs the helper
([docs](https://code.claude.com/docs/en/settings-reference#apikeyhelper)):

- every 5 minutes (`CLAUDE_CODE_API_KEY_HELPER_TTL_MS`),
- when a request fails with `401` or `403`,
- before a request, when the cached output is a JWT that has expired (Claude Code v2.1.246 or later).

The last two only apply when `ANTHROPIC_AUTH_TOKEN` isn't set. The helper's output is sent as both `X-Api-Key` and
`Authorization: Bearer`. Note that `apiKeyHelper` replaces Claude subscription login; for keeping subscription (SSO) auth
through the gateway see [aigw-passthrough-fallback](https://github.com/thresh97/aigw-passthrough-fallback).

## What you need

- A **hybrid** AI Gateway with gateway-local JWT auth (section 2), and a network path from the client to it. For a private
  (VPC-internal) gateway, e.g. `ssh -N -L 18080:<internal-gateway-lb>:80 <host-in-the-vpc>`.
- An OIDC IdP that signs access tokens with **RS256 and a `kid`**, publishes a JWKS URL, and supports the device
  authorization grant (per-user path) and/or client credentials (shared path). Keycloak is used here; Okta, Entra ID, Auth0
  and others have the same grants.
- A workspace with a provider that serves Claude, and the model IDs it serves.
- [`airs-cli`](https://www.npmjs.com/package/@cdot65/prisma-airs-cli) with a tenant selected and rights to read org auth
  settings and deployments, create configs in the workspace and read its logs.
- Claude Code (v2.1.246 or later for renewal on JWT expiry), `bash` (3.2 is fine), `curl`, `jq`, `openssl`.

```bash
export GATEWAY=<gateway-url>                 # e.g. http://127.0.0.1:18080 (tunnel)
TSG=<tsg-id>                                 # airs-cli tenant list
WS=<workspace-slug>                          # airs-cli aigateway workspaces list
WS_ID=$(airs-cli --quiet aigateway workspaces get "$WS" --output json | jq -r .id)
PROVIDER=@<provider-slug>                    # airs-cli aigateway providers list --workspace "$WS_ID"
OPUS=anthropic.claude-opus-5-5 SONNET=anthropic.claude-sonnet-5 HAIKU=anthropic.claude-haiku-4-5   # what PROVIDER serves
```

The model IDs above are the Vertex ones used in testing.

## 1. IdP

What the gateway needs in the access token:

| Claim | Needed | Notes |
|---|---|---|
| `exp` | yes | Keep it short: 5 minutes is a good default. Tests here used 2 minutes. |
| `kid` (header), RS256 | yes | Matches a key in the JWKS URL set on the org. |
| `scope` | conditional | A gateway scope such as `completions.write`, unless the gateway sets `JWT_LOCAL_AUTH_DEFAULT_SCOPES`. |
| `sub` | yes | Used as the user in the logs (`_user`) when there's no email claim. |
| `email_id` / `email` | **leave out** unless the user is a gateway workspace member | A token with an email of a non-member got `403 User is not a member of the resolved workspace` (see [Findings](#findings)). |
| `portkey_oid`, `portkey_workspace` | optional | Org and workspace. A single-org gateway takes them from its own settings (section 2). |
| `defaults.metadata` | optional | Merged into every request's log metadata. (`defaults.config_id` was ignored; see Findings.) |

Two clients:

- **Per user**: a public client (no secret) with the device authorization grant on and PKCE (S256).
- **Shared**: a confidential client with client credentials ("service account") on. Its secret goes in a file only the
  service can read.

Keycloak example, with the admin REST API (`$KC` is the base URL including `/auth` if your Keycloak uses it):

```bash
KC=https://<keycloak>/auth REALM=<realm>
export OIDC_ISSUER=$KC/realms/$REALM
DEVICE_CLIENT=aigw-claude-code SVC_CLIENT=aigw-claude-code-svc
ADMIN=$(curl -s "$KC/realms/master/protocol/openid-connect/token" -d client_id=admin-cli -d grant_type=password \
  -d username=admin --data-urlencode "password@kc-admin.secret" | jq -r .access_token)
kc() { local m=$1 p=$2; shift 2; curl -s -X "$m" "$KC/admin/realms/$REALM$p" -H "authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' "$@"; }
client_id() { kc GET "/clients?clientId=$1" | jq -r '.[0].id'; }
scope_id() { kc GET /client-scopes | jq -r --arg n "$1" '.[] | select(.name == $n) | .id'; }

# The gateway scope: a client scope whose name ends up in the token's `scope` claim
[ -n "$(scope_id completions.write)" ] || kc POST /client-scopes -d '{"name": "completions.write",
  "protocol": "openid-connect", "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"}}'

kc POST /clients -d '{"clientId": "'$DEVICE_CLIENT'", "publicClient": true, "standardFlowEnabled": false,
  "directAccessGrantsEnabled": false, "attributes": {"oauth2.device.authorization.grant.enabled": "true",
  "pkce.code.challenge.method": "S256", "access.token.lifespan": "300"}}'
kc POST /clients -d '{"clientId": "'$SVC_CLIENT'", "publicClient": false, "serviceAccountsEnabled": true,
  "standardFlowEnabled": false, "directAccessGrantsEnabled": false, "attributes": {"access.token.lifespan": "300"}}'

for c in $DEVICE_CLIENT $SVC_CLIENT; do
  kc PUT "/clients/$(client_id $c)/default-client-scopes/$(scope_id completions.write)"   # always in the token
  kc DELETE "/clients/$(client_id $c)/default-client-scopes/$(scope_id email)"            # no email claim
done
(umask 077; kc GET "/clients/$(client_id $SVC_CLIENT)/client-secret" | jq -r .value > aigw-svc.secret)
```

Keycloak shows a consent screen ("Grant access to …") after a device sign-in. The refresh token lives as long as the user's
SSO session: **SSO Session Idle** (default 30 minutes) and **SSO Session Max** in the realm settings. When it runs out, the
next renewal asks the user to sign in again.

## 2. Gateway

Gateway-local JWT auth is set on the hybrid gateway's environment (see Portkey's
[JWT authentication](https://docs.portkey.ai/docs/aigw/product/enterprise-offering/org-management/jwt) page):

| Variable | Value | Why |
|---|---|---|
| `JWT_ENABLED` | `ON` | Validate JWTs on the gateway. |
| `ORGANISATIONS_TO_SYNC` | one org UUID | With a single org, tokens don't need `portkey_oid`. |
| `JWT_LOCAL_AUTH_DEFAULT_SCOPES` | e.g. `completions.write` | Only if your IdP can't put a gateway scope in the token. |

The workspace comes from the token's `portkey_workspace` if it has one, else from the deployment's workspace allowlist (the
first entry), else the org default workspace. And the org needs the IdP's JWKS URL:

```bash
# Org JWKS URL (Keycloak: $OIDC_ISSUER/protocol/openid-connect/certs). Set it in Strata Cloud Manager under the AI Gateway
# organisation's authentication settings if it's empty.
airs-cli --quiet aigateway organisations auth-settings get --tsg-id "$TSG" --output json | jq .data.auth_settings.jwks_url

# The deployment's workspace allowlist (airs-cli aigateway deployments list to find the id)
airs-cli --quiet aigateway deployments get <deployment-id> --output json | jq .auth_settings
```

`auth-settings update` exists too, but the org setting is shared by every gateway and project in the org, so it wasn't
changed in testing.

A routing config. The request has to name one (or a provider) with `x-portkey-config` (see Findings):

```bash
CFG=$(airs-cli --quiet aigateway configs create --workspace "$WS_ID" --name claude-code-jwt \
  --set "config=$(jq -cn --arg p "$PROVIDER" '{provider: $p, request_timeout: 120000}')" --output json)
CFG_ID=$(jq -r .id <<<"$CFG"); CFG_SLUG=$(jq -r .slug <<<"$CFG")
```

## 3. The helper

[`bin/aigw-token`](bin/aigw-token) prints a token on stdout and nothing else. Messages go to stderr; Claude Code shows a failing
helper's stderr in the session, which is how a device sign-in link reaches the user.

```
aigw-token            print an access token (cached, refreshed or re-minted as needed)
aigw-token login      device flow only: show the sign-in URL and wait for approval
aigw-token logout     revoke the refresh token at the IdP and delete the local cache
aigw-token status     show the cached token's claims and expiry (never the token itself)
```

| Variable | Meaning |
|---|---|
| `AIGW_AUTH_MODE` | `device` or `client-credentials` |
| `OIDC_ISSUER` | issuer URL; endpoints come from its `/.well-known/openid-configuration` |
| `OIDC_CLIENT_ID` | client id |
| `OIDC_SCOPE` | scopes to request (optional) |
| `OIDC_CLIENT_SECRET_FILE` | client credentials only: file holding the secret (a trailing newline is ignored) |
| `AIGW_TOKEN_CACHE` | cache dir, default `${XDG_CACHE_HOME:-~/.cache}/aigw-token` (files mode 600) |
| `AIGW_REFRESH_MARGIN` | renew when less than this many seconds are left, default 60 |
| `AIGW_RETRY_WINDOW` | a re-run within this many seconds of handing out a token means the gateway rejected it, default 5 |
| `AIGW_TOKEN_LOG` | optional file, one line per run (what it did, never a token) |

What a run does:

1. A cached access token with more than `AIGW_REFRESH_MARGIN` left: print it.
2. Client credentials: get a new token with the secret.
3. Device: use the refresh token. If that fails (expired or revoked session), check a pending sign-in. If there's none,
   start one. Either way, print "Sign in to the AI Gateway: open <url> and confirm code <code>" to stderr and exit 1. The
   helper never blocks waiting for the browser; the next run (the user's next message) picks up the approved sign-in.
   Polls are spaced by the IdP's interval (5 s by default; it answers `slow_down` to faster polls), so a run may wait up to
   that long.

The retry window exists because Claude Code re-runs the helper after a `401`/`403`, but doesn't say why. Without it, a
cached token the gateway rejects before it expires (key rotation, revoked session) would be handed out again on every retry.
Claude Code's own retries come 1–2 seconds apart, so a quick re-run means "rejected": the helper drops the cached access
token and refreshes or mints. The cost is one extra renewal when two Claude Code processes start within the window.

## 4. Quick check (curl)

```bash
export AIGW_AUTH_MODE=client-credentials OIDC_CLIENT_ID=$SVC_CLIENT OIDC_CLIENT_SECRET_FILE=$PWD/aigw-svc.secret
ask() {  # ask <token>  ->  status and model (or error)
  curl -s -m 60 -o /tmp/b -w 'HTTP %{http_code}  ' "$GATEWAY/v1/messages" \
    -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' -H "x-portkey-config: $CFG_SLUG" \
    -H @<(printf 'authorization: Bearer %s\n' "$1") \
    -d "{\"model\":\"$HAIKU\",\"max_tokens\":10,\"messages\":[{\"role\":\"user\",\"content\":\"Reply: ok\"}]}"
  jq -rc '.model // .error.message // .' /tmp/b
}
ask "$(bin/aigw-token)"        # HTTP 200  claude-haiku-4-5-…
bin/aigw-token status          # claims and expires_in
ask bogus                      # HTTP 401  Portkey Error: Invalid API Key. Error Code: 03
```

For the per-user path, `AIGW_AUTH_MODE=device OIDC_CLIENT_ID=$DEVICE_CLIENT bin/aigw-token login`, open the link, and
then `ask "$(bin/aigw-token)"`.

## 5. Claude Code

Settings (user `~/.claude/settings.json`, or managed settings for a fleet). The helper reads its configuration from the
settings' `env`, so this one file is all a user needs besides the script:

```json
{
  "apiKeyHelper": "/usr/local/bin/aigw-token",
  "env": {
    "ANTHROPIC_BASE_URL": "<gateway-url>",
    "ANTHROPIC_CUSTOM_HEADERS": "x-portkey-config: <config-slug>",
    "ANTHROPIC_MODEL": "anthropic.claude-sonnet-5",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "anthropic.claude-opus-5-5",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "anthropic.claude-sonnet-5",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "anthropic.claude-haiku-4-5",
    "AIGW_AUTH_MODE": "device",
    "OIDC_ISSUER": "https://<keycloak>/auth/realms/<realm>",
    "OIDC_CLIENT_ID": "aigw-claude-code"
  }
}
```

For the shared path set `"AIGW_AUTH_MODE": "client-credentials"`, the service client's id and `OIDC_CLIENT_SECRET_FILE`.
Don't set `ANTHROPIC_AUTH_TOKEN` or `ANTHROPIC_API_KEY`: both take precedence over `apiKeyHelper`, and `ANTHROPIC_AUTH_TOKEN`
also turns off the re-run on `401` and on expiry. `apiKeyHelper` is read from the highest-priority settings file only, so
an `apiKeyHelper` in managed settings wins over a user's.

### End-to-end test

Each run uses a throwaway config dir and an empty environment, so everything comes from the settings file. The long test has
Claude Code run `sleep 70` three times: four model requests over about 3.5 minutes, longer than a 2-minute token.

```bash
cc_run() {  # cc_run <device|client-credentials> <client-id> <prompt> [claude args...]  ->  trace id, result, helper log
  local mode=$1 client=$2 prompt=$3 cfgdir trace; shift 3; cfgdir=$(mktemp -d); trace="cc-jwt-$(date +%s)-$RANDOM"
  jq -n --arg helper "$PWD/bin/aigw-token" --arg gw "$GATEWAY" --arg cfg "$CFG_SLUG" --arg trace "$trace" \
    --arg o "$OPUS" --arg s "$SONNET" --arg h "$HAIKU" --arg mode "$mode" --arg iss "$OIDC_ISSUER" --arg client "$client" \
    --arg secret "$PWD/aigw-svc.secret" --arg cache "$PWD/.cache-$mode" --arg log "$PWD/helper.log" '{
    apiKeyHelper: $helper,
    env: {ANTHROPIC_BASE_URL: $gw, ANTHROPIC_CUSTOM_HEADERS: "x-portkey-config: \($cfg)\nx-portkey-trace-id: \($trace)",
      ANTHROPIC_MODEL: $h, ANTHROPIC_DEFAULT_OPUS_MODEL: $o, ANTHROPIC_DEFAULT_SONNET_MODEL: $s,
      ANTHROPIC_DEFAULT_HAIKU_MODEL: $h, AIGW_AUTH_MODE: $mode, OIDC_ISSUER: $iss, OIDC_CLIENT_ID: $client,
      OIDC_CLIENT_SECRET_FILE: $secret, AIGW_TOKEN_CACHE: $cache, AIGW_TOKEN_LOG: $log}}' > "$cfgdir/settings.json"
  echo "$trace"
  (cd /tmp && env -i PATH="$PATH" HOME="$HOME" CLAUDE_CONFIG_DIR="$cfgdir" claude -p "$prompt" "$@" </dev/null)
  rm -rf "$cfgdir"; tail -5 helper.log
}
logs() {  # logs <trace-id>  ->  time, status and user per request (logs take ~20 s)
  airs-cli --quiet aigateway telemetry logs list --workspace "$WS" --trace-id "$1" --output json |
    jq -r '.data.records | sort_by(.created_at)[] | "\(.created_at)  \(.response_status_code)  \(._user)"'
}
LONG="Run the shell command 'sleep 70' three times, one Bash call at a time. Then reply: done"

cc_run client-credentials $SVC_CLIENT "Reply with just: ok"                         # T1
cc_run client-credentials $SVC_CLIENT "$LONG" --allowedTools 'Bash(sleep:*)'        # T2
cc_run device $DEVICE_CLIENT "Reply with just: ok"                                  # T3: prints a sign-in link
cc_run device $DEVICE_CLIENT "Reply with just: ok"                                  # T4: after approving it
cc_run device $DEVICE_CLIENT "$LONG" --allowedTools 'Bash(sleep:*)'                 # T5
logs <trace-id>
```

Results (Claude Code 2.1.286, gateway_enterprise 2.25.1 hybrid on EKS, Keycloak, 2-minute access tokens, Vertex, 2026-10-01):

| # | Path | Test | Claude Code | Helper / gateway |
|---|---|---|---|---|
| T1 | shared | one turn | `ok` | `minted`; 200 |
| T2 | shared | 4 requests over 3.6 min | `done` | 4 × 200. Helper re-ran once, just before the first request after the token's `exp`: the expiry trigger, not the 5-minute timer |
| T3 | per user | not signed in | `apiKeyHelper failed: exited 1: Sign in to the AI Gateway: open https://…/device?user_code=NDVT-EUVC and confirm code NDVT-EUVC` / `Then send your message again.`, then `Your apiKeyHelper script is failing`; exit 1 | `device flow started`; Claude Code re-ran the helper twice more, which polled and showed the same code |
| T4 | per user | right after approving | `ok`, no second sign-in message | `device flow completed`; 200 |
| T5 | per user | 4 requests over 3.6 min | `done` | 4 × 200, `refreshed` after expiry; `_user` = the user's `sub` |
| T6 | shared | cached token rejected before `exp` (bad signature) | `ok` after 3 s | `cached`, then 1 s later `re-run 1s after handing out a token: assuming it was rejected`, `minted` |
| T7 | per user | `aigw-token logout` | | refresh token revoked (`invalid_grant: Session not active`); next run prints a sign-in link |
| T8 | per user | IdP session ended by an admin | | `refresh rejected: invalid_grant`, then a sign-in link |

T1–T5 were run again on the final helper (T2/T5 with the same result; the README's Keycloak block, curl check and `cc_run`
were run as written, with other client names). Without the retry window (T6), Claude Code re-ran the helper on every retry, with growing gaps (1, 2, 2, 4, 10, 16, 35, 37 s
…), got the same rejected token each time, and never recovered.

### Rolling it out

- Install `aigw-token` somewhere on every machine (it's one bash script) and push the settings above as
  [managed settings](https://code.claude.com/docs/en/settings) with your MDM, so users can't point `apiKeyHelper` elsewhere.
- Per-user: the first message of the day prints a sign-in link; users can also run `aigw-token login` in a terminal
  beforehand. `aigw-token logout` signs out.
- Shared: deliver the client secret as a file readable only by the service user. The access token never touches disk
  anywhere but the cache dir.
- Watch who's using it: requests are logged with `_user` = `sub` and `auth_type=JWT`. Put fields like team or cost center
  in the token as `defaults.metadata` (an IdP claim mapper) and they show up in each request's log metadata.

## 6. Teardown

```bash
airs-cli --quiet aigateway configs delete "$CFG_ID" --force
for c in $DEVICE_CLIENT $SVC_CLIENT; do kc DELETE "/clients/$(client_id $c)"; done
AIGW_AUTH_MODE=device OIDC_CLIENT_ID=$DEVICE_CLIENT bin/aigw-token logout
rm -rf aigw-svc.secret .cache-* helper.log /tmp/b
```

## Findings

Gateway behaviour below is from curl against the test gateway (2.25.1, `JWT_ENABLED=ON`, one org in
`ORGANISATIONS_TO_SYNC`, `JWT_LOCAL_AUTH_DEFAULT_SCOPES=completions.write,mcp.invoke`, one workspace in the deployment
allowlist), with tokens from the shared client unless noted.

| Token | Result |
|---|---|
| valid, `x-portkey-config` header | 200 |
| valid, no `x-portkey-config` (also with `defaults.config_id` in the token) | `400 Either x-portkey-config or x-portkey-provider header is required` |
| valid, `portkey_workspace` = a workspace not in the deployment allowlist | `403 Workspace details not found for <ws>. Error Code: 033` |
| valid, per-user, with `email` or `email_id` | `403 User is not a member of the resolved workspace <ws>. Error Code: 033` |
| expired (accepted earlier while valid) | `401 JWT verification failed: Token has expired` |
| signature tampered | `401 … signature verification failed` |
| signed by another key, unknown `kid` | `401 No matching key found for kid` |
| signed by another key, real `kid` | `401 … signature verification failed` |
| not a JWT | `401 Invalid API Key` |

- **Email claims trigger a workspace membership check.** A per-user token with an email claim was rejected with `403 User is
  not a member of the resolved workspace` when that user isn't an AI Gateway member of the workspace. The same user with no
  email claim got 200 and was logged with `_user` = `sub`. Portkey's docs say a matching email is attributed to that user and
  inherits their workspace role, but not that a non-member is rejected. Either leave email claims out (as here), or make
  every user a workspace member. The member case (an email that *is* a workspace member) wasn't tested.
- **`defaults.config_id` in the JWT was ignored; `defaults.metadata` was applied.** With `{"config_id": "<slug>", "metadata":
  {"team": "…"}}` in the token, requests without `x-portkey-config` still got the 400 above, with or without
  `portkey_oid`/`portkey_workspace` claims. With the header, the log metadata had `team=…`. So send the config in
  `ANTHROPIC_CUSTOM_HEADERS`. Portkey's docs suggest a workspace default config for standard IdP tokens; that wasn't tested.
- **Scopes in the token didn't matter here.** Tokens whose `scope` had no gateway scope (`email profile`) were accepted. The
  docs say `JWT_LOCAL_AUTH_DEFAULT_SCOPES` applies when the token has no `scope`/`scopes` claim; on this gateway it applied
  anyway. Don't rely on the token's scope to restrict access while that variable is set.
- **Workspace without a claim.** A token without `portkey_workspace` landed in the deployment's (only) allowlisted
  workspace. Log metadata: `organisation_id`, `workspace_slug`, `_user` = `sub`, `auth_type=JWT`.
- **Expiry is enforced on every request.** A token that worked while valid got `401 Token has expired` 9 seconds after its
  `exp`. The gateway caches validated tokens, but not past `exp`.
- **The gateway doesn't log `401`s.** Rejected-token requests don't show up in the workspace logs, so watch auth failures on
  the IdP side or in Claude Code's debug log (`claude --debug-file <path>`).
- **A failing helper is re-run quickly.** In `claude -p`, Claude Code ran a failing helper three times, 1–2 seconds apart,
  before giving up. Keycloak answers device-flow polls closer than 5 seconds apart with `slow_down`; before the helper
  spaced its polls, the first message after approving could still show the sign-in link once.
- **Settings `env` reaches the helper.** With an empty environment and everything in `settings.json`, the helper got its
  configuration from the settings' `env`.

## License

[MIT](LICENSE). Provided as-is, with no support and no warranty. This is an example, not an official or recommended product.
