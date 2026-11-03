# Generated functions accept only the Function Access Token

Date: 2026-11-01. Tracks kdex-tech/fngogen#18. Applies to fngogen and fnnodejsgen. The function contract (`FUNCTION_CONTRACT.md`, kdex-tech/kdex-crds#28) records the result.

## Intent

A KDexFunction's `spec.api` may declare several security schemes on an operation: `bearer`, `oauth2`, `apiKeyCookie`, `apiKeyHeader`, `apiKeyQuery` and `oidc` (type `openIdConnect`). **The host honors all of them.**
- The host gate authorizes the request.
- The proxy then forwards a Function Access Token (FAT) in `Authorization: Bearer`. The FAT is a host-signed JWT with `aud` = the function's address. Its `entitlements` claim holds the caller's role-resolved grants.

**The generated function does not mirror this.** It runs a separate handler per scheme, and two of them read the wrong claim:
- The `oauth2` and `openIdConnect` handlers read a `scopes` claim. No host-minted token carries one, so every oauth2-only or openIdConnect-only operation refuses every caller.
- The `apiKey*` handlers verify the raw PASETO API key, which the proxy also forwards, and authorize on its `scp` claim.
  - `scp` comes from the mint request's body. The mint handler never checks it against what the subject holds. host-manager treats it as revocation metadata.
  - So a caller who reaches the function directly can grant themselves any authority.
  - Through the proxy, a developer key minted for the host audience fails the function's own audience check.

**The fix:** a generated function accepts exactly one credential, the FAT, and authorizes on its `entitlements` claim against the operation's requirement strings, whatever scheme they were declared under.
- The host keeps every scheme.
- The published API description keeps every scheme.
- Only the function's own check narrows.

## Goals

- Every generated operation that declares security verifies the FAT from `Authorization: Bearer` and authorizes on `entitlements`. Nothing else is checked: no PASETO, no `scp`, no `scope`/`scopes`, no `X-API-TOKEN` cookie/header, no `api_token` query.
- The function's decision matches the gate's on every request that came through the proxy. An operation the gate admits, the function admits, and the reverse.
- OR-of-AND semantics are preserved exactly. An operation's `security` list is a list of alternatives, and each alternative is satisfied when the FAT's `entitlements` hold every requirement string in it, across all of its schemes.
- Optional authentication works. An empty alternative `{}` admits a caller with no token. A caller whose FAT lacks the permission falls through to `{}` instead of being refused.
- Requirement `{placeholder}` binding (fngogen#15, `x-entitlement-binding`) keeps working unchanged.
- fngogen and fnnodejsgen behave identically.

## Non-goals

- **No host-manager change.**
  - The proxy, the gate, `/-/apitokens/mint` and the token endpoint stay as they are.
  - In particular `/-/apitokens/mint` keeps accepting any `aud` and `scp`.
  - No new endpoint issues a FAT to a person.
- **Service-backed functions (`spec.backend`, e.g. knowdb) are out of scope.** They run their own auth. knowdb is separately dropping its `X-API-Key` path (mmstore #1017) and will accept only the host's bearer token.
- **Callback endpoints the host itself calls** (event hooks, HTTP lookups such as user-credential-check) are unchanged. They authenticate with HMAC, not a declared security scheme.
- **Re-scaffolding deployed functions is out of scope.**
  - knowdrive-site's functions are `regenerate: false`, and eum pins fngogen 0.6.3.
  - None of them declares a non-bearer scheme, so nothing deployed changes behavior.
  - Each owner picks the change up at their next re-scaffold or pin bump.

## Anti-goals (would make this a failure even if it works)

- **The function admitting a caller the gate refuses.** Reading `scope` would do this: it is whatever the client asked for, and a client_credentials grant's scope is not filtered. That is why the host keeps scope bucketing off (`authorization.go` `AuthorizationChecker.scopeBuckets`).
- **Collapsing alternatives into one AND list.** ogen does this when several alternatives use the same scheme (see Constraints). Relying on it would make the function refuse callers the gate admitted.
- **Changing what the published `/-/openapi` or the host gate sees.** The rewrite is internal to code generation.

## Constraints and facts the design rests on

- **The FAT.**
  - The proxy mints it for every request with an authenticated identity (`kdex-host-manager internal/host/proxy.go`, `reverseProxyHandler`). `aud` is `fatAudienceFor(fn)`, which matches the function's `AUDIENCE` env (`http://<name>.<ns>.svc.cluster.local`).
  - It carries `entitlements` whenever the caller's context had them. `Project` copies the claim and does not apply scope confinement.
  - A caller whose token was issued without the `entitlements` scope produces a FAT with no `entitlements` claim. The gate treats such a caller as holding nothing.
- **How the gate treats each scheme today** (`authorization.go` `GetParsedEntitlements`; `internal/host/proxy_pat_realgate_test.go` ~L42: "nothing in the codebase ever populates an apiKey* bucket"):

  | Alternative declared under | Satisfied at the gate by |
  |---|---|
  | `bearer` | `entitlements`, for every authenticated caller (including API keys turned into a FAT by the bridge) |
  | `oauth2` | `entitlements`, but only for API-key/PAT-bridge callers |
  | `apiKeyCookie` / `apiKeyHeader` / `apiKeyQuery` | never. Declaring one only switches on the PAT bridge for the function (`acceptsAPIKey`), which then authorizes through a `bearer` alternative |
  | `oidc` | never (scope bucketing is off) |

  The gate also requires `functions:<basePath>:read` on every request. Two paths reach a function without the gate:
  - an exchanged FAT (`kdexauth.Exchange`);
  - a `client_credentials` + `resource` token.

  On those paths the function's check is the only one.
- **Anonymous requests get no FAT.** The proxy deletes `Authorization`.
  - A function's ops reach anonymous callers only when they declare `security: []` (no auth) or include an empty alternative `{}` (optional auth).
  - At the gate, an empty alternative is a requirement with nothing to satisfy. Anonymous reach to the function as a whole still needs `functions:<basePath>:read` from the host's anonymous set, as today's public ops already do.
  - The host never injects `ANONYMOUS_ENTITLEMENTS` into a function, and the function does not apply the host's anonymous set to op-level requirements.
- **ogen behavior** (verified 2026-11-01 with `ogen@latest`):
  - An empty alternative `{}` compiles to an always-satisfied requirement.
  - A scheme's security handler returning `ogenerrors.ErrSkipServerSecurity` marks that scheme as not satisfied, so evaluation moves on to the other alternatives. Any other error fails the request immediately.
  - `operationRoles<Scheme>` is ONE list per operation per scheme. `[{bearer:[a]},{bearer:[b,c]}]` yields roles `[a,b,c]`, which the generated handler then checks as one AND. **The generated code must not authorize from ogen's roles.** It must use its own per-operation table of the original alternatives.
- **fngogen already rewrites the spec before ogen runs:** `fngogen --prepare` (`entry-point.sh` line 18, today used for SSE raw handlers). The security rewrite belongs in that step.
- **fngogen already emits per-operation tables** keyed by `METHOD route-pattern` (`entitlementBindings` in `main.go.tmpl`). The requirement table follows the same pattern.
- **fnnodejsgen does not use ogen.** It parses `security` itself into `operationSecurity` (an array of clauses per method) and evaluates clauses in `verifyOperation` (`src/emit/auth.ts`). It extracts a token per scheme today.

## Decided design

### fngogen

1. **Spec rewrite in `--prepare`.**
   - Rewrite every operation's `security`, and any top-level `security`, so that every non-empty alternative becomes `{bearer: [<union of that alternative's requirement strings across its schemes>]}`.
   - Empty alternatives `{}` stay as they are.
   - `components.securitySchemes` is reduced to a single `bearer` (`type: http`, `scheme: bearer`, `bearerFormat: JWT`) whenever any operation still declares security.
   - The original alternatives are captured first for step 2.
   - The prepared spec feeds only ogen and fngogen.
2. **Per-operation requirement table.**
   - Emit `operationRequirements map[string][][]string` into `main.go`, keyed like `entitlementBindings`.
   - Each inner slice is one alternative's union of requirement strings, from the original spec.
   - `{}` alternatives are omitted from the table, because ogen handles them.
3. **One security handler.**
   - `HandleBearer` verifies the JWT as today: JWKS, `aud`, `iss`, required `exp`.
   - It then authorizes on `entitlements` against the operation's alternatives from `operationRequirements`. Placeholder binding applies to each alternative as today.
   - A missing `entitlements` claim is treated as an empty list, not as an error.
   - **On no alternative satisfied, return `ogenerrors.ErrSkipServerSecurity`.** For an op without `{}`, ogen then answers 401 exactly as before. For an op with `{}`, the request proceeds without claims.
   - An invalid token (signature, `aud`, `iss`, `exp`) stays a hard error.
4. **Delete the other handlers.** Remove `handleApiKey`, `HandleApiKey*`, `HandleOAuth2` and `HandleOpenIdConnect`, the PASETO key fetching (`PASETO_PKS_URL`) and the token-prefix restore. Also remove the `APIKey*Security` / `OAuth2Security` / `OpenIdConnectSecurity` template flags.
5. **Keep** `RequestTokenContextKey` / `RequestTokenFromContext` (the FAT is what `kdexauth.Exchange` forwards) and the verified token's claims under `UserContextKey` (set directly; there is one handler per call, so nothing is merged).
6. **This supersedes the interim fix.** The unpushed interim commit `0ddd4f8` (oauth2/oidc → `entitlements`) stops mattering once those handlers are gone. Its test `TestGenerate_OAuth2ReadsEntitlements` is reworked to assert the new behavior for an oauth2-declared fixture: an `entitlements` token is admitted, and tokens with only `scope` or `scopes` are refused.

### fnnodejsgen

- Same semantics, applied in its own parse/emit step.
- Every clause's token comes from `Authorization: Bearer` and is verified as a JWT. Each non-empty clause is satisfied when `entitlements` hold the union of its requirement strings, and an empty clause admits.
- Remove PASETO verification, `scp`, and per-scheme token extraction. The interim commit `25a5902` is superseded the same way.

### Contract (kdex-crds#28, `FUNCTION_CONTRACT.md`)

Record:
- A generated function's only credential is the FAT in `Authorization: Bearer`, and its only authority is the `entitlements` claim.
- `scp` grants nothing, even though the FAT carries it.
- Declared schemes other than `bearer` are honored by the host, not by the function.
- Operations open to anonymous callers must say so: `security: []`, or an empty alternative `{}`. The host's anonymous set is not applied to op-level requirements by the function.
- Direct in-cluster calls (troubleshooting, load tests) use a confidential client with `allowed-resources` naming the target's `basePath`, through `client_credentials` with `resource=<basePath>`. The client's `entitlements` apply, not the caller's own.
  - Verified on dev 2026-11-01 against knowdb: resource token → 200, host-audience token → 401, no token → 403.
  - infra has moved its recipes to this (`tools/knowdb-search-loadtest/get-token.sh`, client `knowdb-loadtest`).

## Tests the builder must include

- Rewrite unit tests:
  - mixed schemes per alternative are unioned;
  - several alternatives under one scheme stay separate;
  - `{}` is preserved;
  - top-level `security` is handled;
  - `securitySchemes` is reduced;
  - a spec with no security is untouched.
- Generated-function probes (the existing `writeJWTProbeHelpers` style, driving the generated server over HTTP):
  - `[{bearer:[a]},{bearer:[b,c]}]`: holding `a` alone is admitted, holding `b,c` is admitted, holding `b` alone is refused. This pins the anti-goal.
  - `[{}, {bearer:[a]}]`: no token is admitted; a FAT without `a` is admitted, with no claims in context; a FAT with `a` is admitted, with claims in context.
  - An oauth2-only and an apiKey-only fixture: an `entitlements` FAT is admitted. A PASETO in `X-API-TOKEN` / `X-API-Key` / `api_token` with any `scp` is refused.
  - A FAT with no `entitlements` claim on a required op → 401, not 500.
  - Placeholder binding (`TestGenerate_BearerBindsRequirementPlaceholders`) still passes.
- fnnodejsgen: emitted-code tests for the same matrix, as far as its test harness allows.

## Related but separate (not in this design)

- **Proxy bug, to be filed against host-manager:** when `Project` or `SignProjected` fails, the proxy neither sets nor deletes `Authorization`, so the caller's own host token reaches the function (`proxy.go` ~L252-271).
- **Lint toolchain:** local `make lint` needs `GOTOOLCHAIN=go1.26.0` under Homebrew Go 1.27.3 with golangci-lint v2.13.2 (kdex-entitlements already bumped to v2.15.0 for this).

## Decided: every scheme is treated the same at the function

The function cannot mirror the gate's per-scheme buckets exactly (see the table above): the FAT does not record whether the caller came through the PAT bridge. Two options were weighed.

- **Chosen: scheme-agnostic.** Any non-empty alternative is satisfied when `entitlements` holds the union of its strings.
  - Through the proxy this changes nothing, because the gate decides first.
  - It is looser than the gate only on the two paths that skip the gate, and only for alternatives the gate cannot satisfy (apiKey-only, oidc-only, oauth2 for non-bridged callers). On both paths the token is host-issued and its `entitlements` are host-resolved, so admitting on them is still the host's authority, never the caller's own assertion.
  - No generated function in the fleet declares such alternatives today.
- **Rejected: honor only `bearer` alternatives.** It would refuse every bridged MCP client on an oauth2-only generated operation, which the gate admits. It would also need a special rule so that an operation left with no alternatives refuses everyone instead of becoming unsecured.

## Calls made by the designer (check these)

- **fnnodejsgen placeholder binding is out of scope.** fnnodejsgen has no `x-entitlement-binding` support today, and nothing in the fleet uses fnnodejsgen. "Behave identically" here covers the credential and scheme handling only. A follow-up issue tracks binding parity.
- **HTTP status codes stay as each generator has them.**
  - fngogen answers 401 for every security failure, through ogen.
  - fnnodejsgen answers 401 for a missing or invalid token and 403 for an entitlements mismatch.
  - The "FAT with no `entitlements` claim" test therefore expects 401 in fngogen and 403 in fnnodejsgen.
  - Aligning fngogen with the denial contract's 401/403 split needs a custom ogen error handler. That is a separate follow-up.
- **The function does not add the gate's `functions:<basePath>:read` identity check.**
  - Adding it could refuse existing gate-bypassing callers whose client holds no such grant, e.g. eum → blobsqlite with resource `/db/v1`.
  - Whether bypass paths should carry that check is a separate follow-up.
- **The release stops at tagging fngogen and fnnodejsgen** (after the quad).
  - Bumping nexus-manager's bundled default adaptor (`kdex-nexus-manager/config/faas/kdex-default-faas-adaptor-knative.yaml`, `fngogen:0.6.3`) is a separate step on the user's go.
  - Before that bump, check that no deployed spec declares a non-bearer scheme. The 2026-11-01 audit found none outside knowdb, which is service-backed.
- **The contract update waits for kdex-crds#28.** `FUNCTION_CONTRACT.md` exists only on #28's unmerged branch, which belongs to another session. The required text goes onto #28 as a comment now, and into the file once #28 merges.
- **fngogen lands on `main` independently of fngogen PR #17.** Whichever merges second rebases. The conflicts in `cmd/main.go` are mechanical.

## Left to the builder

- Exact Go and TS names for the table and helpers, and the error messages.
- Whether the rewrite also normalizes a `bearer` scheme that has a different component name.
- How fnnodejsgen's tests exercise the emitted auth (text assertions vs. running the emitted code).
- Version bumps: fngogen minor (behavior change for apiKey/oauth2/oidc declarations), fnnodejsgen minor.
