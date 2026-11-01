# Generated Functions Accept Only the FAT: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** fngogen- and fnnodejsgen-generated functions verify only the host-minted Function Access Token (FAT, `Authorization: Bearer` JWT) and authorize on its `entitlements` claim against each operation's alternatives, whatever scheme each alternative was declared under.

**Architecture:**
- **fngogen.** `--prepare` (which already runs before ogen) rewrites `security` so that every non-empty alternative becomes `{bearer: <union of its strings>}`, and keeps `{}`. ogen then generates only `HandleBearer`.
  - ogen merges same-scheme alternatives into a single AND, so the generated code does not use its roles. It authorizes from its own `operationRequirements` table, keyed `METHOD /path` like `entitlementBindings`. The route key reaches the handler on the request context set by `bindRequestPlaceholders`.
  - When nothing is satisfied, the handler returns `ogenerrors.ErrSkipServerSecurity`, so a `{}` alternative can still admit.
- **fnnodejsgen** normalizes the same way while parsing. Its emitted auth then has only a JWT bearer path.

**Tech Stack:** Go 1.26 (fngogen, ogen@latest, golang-jwt v5, `github.com/kdex-tech/entitlements/go`), TypeScript (fnnodejsgen, vitest, fastify, jose, `@kdex-tech/entitlements`).

**Spec:** `kdex-fngogen/docs/superpowers/specs/2026-11-01-fat-only-function-security-design.md` (approved 2026-11-01). Read it first.

## Global Constraints

- Repos: `/home/rotty/projects/kdex/workspace/kdex-fngogen` (Tasks 1–4) and `/home/rotty/projects/kdex/workspace/kdex-fnnodejsgen` (Tasks 5–6). Commit inside each repo. Do not push and do not tag; the release follows a quad.
- **Scheme-agnostic:** any non-empty alternative is satisfied when the FAT's `entitlements` hold every string in the union of that alternative's schemes. An empty alternative `{}` admits with no token.
- **Never read** `scope`, `scopes`, `scp`, a PASETO, the `X-API-TOKEN` cookie/header or the `api_token` query.
- **A missing `entitlements` claim means an empty list,** never an error.
- **An invalid JWT is a hard error.** That covers signature, `aud`, `iss`, and a missing or zero `exp` (`parseJWT` already enforces these). It is never a skip.
- **Status codes are unchanged per generator.** fngogen: 401 for every security failure. fnnodejsgen: 401 for a missing or invalid token, 403 for an entitlements mismatch.
- **Do not add** a `functions:<basePath>:read` check, fnnodejsgen placeholder binding, or any host-manager change.
- Go lint: `GOTOOLCHAIN=go1.26.0 make lint` (Homebrew Go 1.27.3 breaks golangci-lint v2.13.2).
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **An operation's own `security: []` under a top-level `security`** must stay unauthenticated. The rewrite must not touch it. The fngogen table must have no entry for it (Task 1 and Task 2 tests).
2. **Non-operation keys in a path item** (`parameters`, `summary`, `x-kdex-metadata`, which every fixture carries) must be skipped by the rewrite and the table (Task 1 and Task 2 tests).
3. **The same string under two schemes of one alternative** (`{oauth2:[a], apiKeyHeader:[a]}`) yields `[a]` once (Task 1 test).
4. **An alternative with an unbound `{placeholder}`** must count as unsatisfied, not refuse the whole operation, when another alternative is satisfied (Task 3 probe).
5. **An `entitlements` claim sent as a space-separated string** instead of an array must still authorize, as `hasValidClaims` does today (Task 3 probe).

---

### Task 1: fngogen: rewrite `security` to bearer-only in `--prepare`

**Files:**
- Create: `cmd/prepare_security.go`
- Modify: `cmd/prepare.go` (`prepareSpec` calls the new function; update its doc comment: it now also rewrites security)
- Test: `cmd/prepare_security_test.go`

**Interfaces:**
- Produces: `func bearerOnlySecurity(doc map[string]any) bool`. It mutates `doc` and reports whether anything changed. Also `const bearerSchemeName = "bearer"`, and `var operationMethods = []string{"get","put","post","delete","options","head","patch","trace"}`; reuse `bindingMethods` from `binding.go` if it is the same list.
- Produces: `func unionAlternative(alt map[string]any) []string`, used by Task 2. It takes the strings of every scheme in the alternative, in sorted scheme-name order, keeping first occurrence and dropping duplicates. It returns `[]string{}` (not nil) for an alternative whose schemes list no strings.

Rules:
- A non-empty alternative becomes `{"bearer": unionAlternative(alt)}`.
- `{}` stays `{}`.
- An operation without a `security` key is left alone. The top-level `security` is rewritten by the same rule.
- When any `security` remains anywhere, `components.securitySchemes` becomes exactly `{"bearer": {"type":"http","scheme":"bearer","bearerFormat":"JWT"}}`.
- A spec with no `security` anywhere and no `securitySchemes` is untouched (returns false).

- [ ] **Step 1: Write the failing tests** in `cmd/prepare_security_test.go`, as table tests over JSON docs. Assert the post-rewrite `security` and `securitySchemes`:
  - `[{"oauth2":["b","a"],"apiKeyHeader":["a","c"]}]` → `[{"bearer":["a","c","b"]}]` (sorted scheme order: apiKeyHeader, then oauth2; the duplicate `a` is dropped)
  - `[{"bearer":["a"]},{"bearer":["b","c"]}]` → unchanged alternatives (two entries)
  - `[{},{"oidc":["x"]}]` → `[{},{"bearer":["x"]}]`
  - `[{"apiKeyCookie":[]}]` → `[{"bearer":[]}]`
  - top-level `[{"oauth2":["a"]}]` with one op `security: []` and one op with no key → top-level `[{"bearer":["a"]}]`, op `[]` unchanged, the other op has still no `security` key
  - a path item carrying `parameters` and `x-kdex-metadata` next to `put` → no panic, the extras are untouched
  - schemes `{"jwt":{type:http,scheme:bearer},"apiKeyHeader":{…}}` with `[{"jwt":["a"]}]` → schemes reduced to the single `bearer` entry, security `[{"bearer":["a"]}]`
  - no security anywhere → returns false and the doc is deep-equal to its input
- Also extend `TestPrepareSpec_NoSSEIsUnchanged`'s intent: a bearer-only spec whose `security` is already `{bearer:[…]}` and whose schemes are already exactly the canonical `bearer` entry returns `changed == false`.

- [ ] **Step 2: Run them and confirm they fail**
  Run: `cd cmd && go test . -run 'TestBearerOnlySecurity|TestPrepareSpec' -count=1`
  Expected: FAIL (`bearerOnlySecurity` undefined).

- [ ] **Step 3: Implement `bearerOnlySecurity` and `unionAlternative`,** and call `changed = bearerOnlySecurity(doc) || changed` in `prepareSpec` before marshalling. Compare against the canonical form so an already-prepared spec reports no change.

- [ ] **Step 4: Run the tests and confirm they pass**
  Run: `cd cmd && go test . -run 'TestBearerOnlySecurity|TestPrepareSpec' -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit**
  `git add cmd/prepare_security.go cmd/prepare_security_test.go cmd/prepare.go && git commit -m "feat(prepare): rewrite security to bearer-only alternatives (#18)"`

### Task 2: fngogen: per-operation requirement table

**Files:**
- Create: `cmd/requirements.go`
- Test: `cmd/requirements_test.go`

**Interfaces:**
- Consumes: `unionAlternative`, `operationMethods`, `bearerSchemeName` (Task 1).
- Produces: `func operationRequirements(spec map[string]any) map[string][][]string`. Keys are `strings.ToUpper(method) + " " + path`, exactly the key format of `entitlementBindings` in `binding.go`. Values are one `[]string` per non-empty alternative, from `unionAlternative`, in declaration order.
  - An operation inherits the top-level `security` when it has no `security` key.
  - An operation whose effective security is `[]`, or contains only `{}` alternatives, has no entry.
  - An operation with both `{}` and non-empty alternatives has an entry listing only the non-empty ones.
  - It works on both a prepared and an unprepared spec, with the same result.

- [ ] **Step 1: Write the failing tests:**
  - `TestOperationRequirements_KeepsAlternativesSeparate`: `[{"bearer":["a"]},{"bearer":["b","c"]}]` on `PUT /v1/x/{id}` → `{"PUT /v1/x/{id}": {{"a"},{"b","c"}}}`
  - `_UnionsSchemes`: `[{"oauth2":["a"],"apiKeyHeader":["a"]}]` → `{{"a"}}`
  - `_OptionalAuth`: `[{},{"bearer":["a"]}]` → `{{"a"}}`; `[{}]` → no key
  - `_TopLevelInheritance`: top-level `[{"bearer":["t"]}]`; op A has no key → `{{"t"}}`; op B has `[]` → no key
  - `_AuthenticatedOnly`: `[{"apiKeyQuery":[]}]` → `{{}}`, i.e. one alternative with an empty, non-nil slice
  - `_PreparedEqualsUnprepared`: for `test-fixtures/openapi-spec-oauth2.json`, the table equals the one for `prepareSpec`'s output
- [ ] **Step 2: Run** `cd cmd && go test . -run TestOperationRequirements -count=1`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement `operationRequirements`.**
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat: per-operation requirement table for generated security (#18)`

### Task 3: fngogen: generated `HandleBearer` authorizes from the table, and the other handlers go

**Files:**
- Modify: `cmd/main.go`
  - `TemplateData`: remove `APIKeyCookieSecurity`, `APIKeyHeaderSecurity`, `APIKeyQuerySecurity`, `BearerSecurity`, `OAuth2Security` and `OpenIdConnectSecurity`.
  - Add `OperationRequirements map[string][][]string`.
  - `Security` = "any `components.securitySchemes` present".
  - `run()` sets `OperationRequirements: operationRequirements(spec)`.
- Modify: `cmd/templates/main.go.tmpl`.
- Modify: `cmd/templates/custom.go.tmpl` / `custom_raw.go.tmpl` / `default.go.tmpl`, only where they reference removed flags (check with `rg -n 'APIKey|OAuth2Security|OpenIdConnect|BearerSecurity' cmd/templates`).
- Test: `cmd/main_test.go`, plus new fixtures `test-fixtures/openapi-spec-bearer-alternatives.json` and `test-fixtures/openapi-spec-optional-auth.json`.

**Interfaces:**
- Consumes: `operationRequirements` (Task 2); the prepared spec (Task 1) via `generateFixture`.
- Produces (generated code):
  - `var operationRequirements = map[string][][]string{…}`, rendered like `entitlementBindings`.
  - `type routeKeyContextKey struct{}`.
  - `bindRequestPlaceholders` additionally stores `r.Method+" "+route.PathPattern()` under `routeKeyContextKey{}`.
  - `func (s *security) HandleBearer(ctx context.Context, operationName api.OperationName, t api.Bearer) (context.Context, error)`.
  - `func (s *security) authorize(ctx context.Context, claims jwt.MapClaims) (context.Context, bool, error)`: `ok == false, err == nil` means not satisfied; `err != nil` means a wiring or claims error.

`HandleBearer` behavior:
1. `parseJWT`. On failure, return the error, as today.
2. Missing `sub` → hard error, as today.
3. `entitlements`: absent → `[]`. A string → `strings.Fields`. `[]any` → strings. Any other type → hard error, as today.
4. Read the route key from the context. If absent → hard error, keeping today's message `no request binding (is srv.Handler wrapped, not replaced?)`.
5. For each alternative in `operationRequirements[key]`: bind that alternative alone with `BindRequirements`, where a bind error means the alternative is not satisfied. Then verify `{bearer: ents}` against `{bearer: alt}`. The first satisfied alternative wins.
6. Satisfied → `context.WithValue(ctx, RequestTokenContextKey, t.Token)` (keep this exact expression, `TestGenerate_BearerHandlerFlowsRawToken` asserts it), then `mergeClaims`, then return.
7. Not satisfied, or no table entry → return `ogenerrors.ErrSkipServerSecurity`. Import `github.com/ogen-go/ogen/ogenerrors`.

Delete:
- `handleApiKey` and `HandleApiKeyCookie`/`Header`/`Query`;
- `HandleOAuth2` and `HandleOpenIdConnect`;
- `pasetoPKs`, `PASETO_PKS_URL` and `PASETO_TOKEN_PREFIX` handling, and the `pks`/`tokenPrefix` fields;
- the paseto, `encoding/base64` and `sync` imports;
- `hasValidClaims`, which `authorize` replaces.

- [ ] **Step 1: Write the fixtures.**
  - `openapi-spec-bearer-alternatives.json`: copy `openapi-spec-bearer.json`, with `PUT /v1/users/{id}` security `[{"bearer":["a"]},{"bearer":["b","c"]}]`.
  - `openapi-spec-optional-auth.json`: the same op with `[{},{"bearer":["a"]}]`, plus a second op `PUT /v1/roles/{key}` with `[{"bearer":["roles:{key}:update"]},{"bearer":["z"]}]`.
- [ ] **Step 2: Write the failing HTTP probes.** Follow `TestGenerate_BearerBindsRequirementPlaceholders`: generate with `generateFixture`, run `go main()` on a free port, and drive it over HTTP. Admitted = the stub's 500; refused = 401.
  - `TestGenerate_BearerAlternativesStaySeparate` (fixture `bearer-alternatives`): ents `[a]` → admitted; `[b,c]` → admitted; `[b]` → refused; `[]` → refused; ents given as the string `"b c"` → admitted; a FAT with **no `entitlements` claim** → refused (401, not 500).
  - `TestGenerate_OptionalAuthFallsThrough` (fixture `optional-auth`): on `/v1/users/u1`, no Authorization → admitted; FAT with ents `[x]` → admitted; FAT with ents `[a]` → admitted; FAT with **no `entitlements` claim** → admitted; FAT with a bad signature → refused (401). On `/v1/roles/analysts`, ents `[z]` → admitted (the alternative with an unbound placeholder is skipped, not fatal); ents `[roles:analysts:update]` → admitted; ents `[]` → refused.
  - `TestGenerate_SkipKeepsClaimsOutOfContext`: a probe test calls `s.HandleBearer` directly with a context carrying the route key and a binding. For ents `[x]` on the optional-auth op, assert `errors.Is(err, ogenerrors.ErrSkipServerSecurity)`. For `[a]`, assert the returned context has `UserContextKey` claims with `sub == "alice"`.
- [ ] **Step 3: Run** `cd cmd && go test . -run 'TestGenerate_(BearerAlternatives|OptionalAuth|SkipKeeps)' -count=1`. Expected: FAIL. `[b,c]` is refused today (ogen ANDs a,b,c), and a FAT without `a` on the optional op is refused.
- [ ] **Step 4: Implement** the `TemplateData` change and the template change described above.
- [ ] **Step 5: Run** the three new tests, plus `TestGenerate_BearerBindsRequirementPlaceholders`, `TestGenerate_BearerRequiresExp` and `TestGenerate_BearerHandlerFlowsRawToken`. Expected: PASS.
- [ ] **Step 6: Commit** `feat: generated security authorizes the FAT against each alternative (#18)`

### Task 4: fngogen: non-bearer declarations are served by the FAT

**Files:**
- Modify: `cmd/main_test.go`
  - `Test_run`: insert `run([]string{"--prepare","--spec",tt.openapi})`, run on a copy written into the work dir (mirror `generateFixture`), before `go generate`.
  - Un-comment the `openapi-spec-openIdConnect.json` case with its own `workDir`.
  - Replace `TestGenerate_OAuth2ReadsEntitlements` (from interim commit 0ddd4f8).

**Interfaces:**
- Consumes: everything from Tasks 1–3.

- [ ] **Step 1: Write the failing probe `TestGenerate_NonBearerSchemesAcceptOnlyTheFAT`.** It loops over the oauth2, openIdConnect, apiKey-header, apiKey-cookie and apiKey-query fixtures. Each generates and runs `main()`, and sends:
  - a FAT whose `entitlements` hold that op's strings (oauth2: `users:read users:write`; oidc: `email`; apiKey: any valid FAT, since `[]` means authenticated only) → admitted;
  - a FAT whose `entitlements` lack them → refused (apiKey: skip this case);
  - a FAT with only `scope: "users:read users:write"` or only `scopes: [...]` → refused (oauth2 and oidc);
  - no Authorization, but `X-API-TOKEN: v4.public.x` header, `X-API-TOKEN` cookie and `?api_token=v4.public.x` → refused, 401.
  - Also assert that the generated `cmd/main.go` contains no `paseto`, `HandleApiKey`, `HandleOAuth2` or `HandleOpenIdConnect`.
- [ ] **Step 2: Run** `cd cmd && go test . -run 'TestGenerate_NonBearer|Test_run' -count=1`. Expected: FAIL until `Test_run` prepares (the oidc case does not generate with ogen unprepared) and the probe exists.
- [ ] **Step 3: Make the `Test_run` change and delete `TestGenerate_OAuth2ReadsEntitlements`.**
- [ ] **Step 4: Run** `make test` (repo root). Expected: `ok github.com/kdex-tech/fngogen/cmd` and `ok …/runtime/kdexauth`. Then `GOTOOLCHAIN=go1.26.0 make lint` → `0 issues.`
- [ ] **Step 5: Commit** `test: non-bearer declarations are served by the FAT alone (#18)`

### Task 5: fnnodejsgen: normalize security to bearer-only at parse

**Files:**
- Modify: `src/parse.ts`. Add an exported `bearerOnly`, apply it to every operation's security and to the IR's `securitySchemes`/`securityFlags`.
- Test: `src/parse.test.ts`.

**Interfaces:**
- Produces: `export function bearerOnly(reqs: SecurityRequirement[]): SecurityRequirement[]`, with the same union rule and order as fngogen's `unionAlternative`:
  - sorted scheme names; first occurrence kept;
  - `{}` kept;
  - `{x: []}` → `{bearer: []}`;
  - non-empty alternatives first, `{}` alternatives last, so a valid FAT populates claims before the empty alternative admits.
- After parse:
  - `ir.securitySchemes` is `{bearer: {kind: "bearer"}}` (use the existing normalized scheme shape from `src/emit/security.ts`) when any security remains, else `{}`.
  - `ir.securityFlags` is computed from it, so `apiKey*`, `oauth2` and `openIdConnect` are always false.

- [ ] **Step 1: Write the failing tests** in `src/parse.test.ts`:
  - `bearerOnly([{oauth2:["b","a"], apiKeyHeader:["a","c"]}])` → `[{bearer:["a","c","b"]}]`
  - `bearerOnly([{}, {oidc:["x"]}])` → `[{bearer:["x"]}, {}]`
  - `bearerOnly([{bearer:["a"]},{bearer:["b","c"]}])` → unchanged
  - parsing `openapi-spec-apikey-header.json` → `securityFlags.apiKeyHeader === false`, `securityFlags.bearer === true`, and the op's security is `[{bearer:[]}]`
  - parsing `openapi-spec-oauth2.json` → `securityFlags.oauth2 === false`
  - Update the existing assertions at `parse.test.ts:58-60` that expect `apiKeyHeader === true`.
- [ ] **Step 2: Run** `npx vitest run src/parse.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement** `bearerOnly` and apply it in `parseSpec`.
- [ ] **Step 4: Run** `npx vitest run src/parse.test.ts`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(parse): normalize security to bearer-only alternatives (kdex-tech/fngogen#18)`

### Task 6: fnnodejsgen: emitted auth has only the JWT bearer path

**Files:**
- Modify: `src/emit/auth.ts`
  - Remove `verifyPaseto`, the `usesPaseto` branches, the apiKey and cookie arms of `extractToken`, and `claimKeyForScheme`. Entitlements always come from `entitlements`.
  - Missing `entitlements` claim → `[]`; `entitlementsFromClaims` already does this.
- Modify: `src/emit/package-json.ts`. Drop the `paseto` and `@fastify/cookie` dependency branches.
- Test: `src/cli.test.ts`. Replace the `"auth.ts reads entitlements for every JWT scheme"` block from interim commit 25a5902.

**Interfaces:**
- Consumes: `bearerOnly` (Task 5), via the IR.

- [ ] **Step 1: Write the failing tests** in `src/cli.test.ts`. For each of the oauth2, openIdConnect, apikey-header, apikey-cookie and apikey-query fixtures, the emitted `src/auth.ts`, with comments stripped, must not match `/paseto|verifyPaseto|"scp"|"scopes?"|X-API-TOKEN|api_token/`, and must contain `entitlementsFromClaims(claims, "entitlements")`. The emitted `package.json` must not list `paseto` or `@fastify/cookie`. Also add the existing `tsc --noEmit` compile check for `openapi-spec-apikey-header.json`.
- [ ] **Step 2: Run** `npx vitest run src/cli.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement** the emitter changes.
- [ ] **Step 4: Run** `npm test && npm run lint`. Expected: all tests pass and eslint is clean. Prettier's existing warnings are pre-existing and out of scope.
- [ ] **Step 5: Commit** `feat(auth): verify only the FAT bearer token (kdex-tech/fngogen#18)`

### Task 7: Follow-ups and contract text (no code)

- [ ] **Step 1: Comment on kdex-tech/kdex-crds#28** with the contract text from the spec's "Contract" section, including the client_credentials + `resource` recipe for direct calls (`get-token.sh knowdb-loadtest dev /api/v1/search`).
- [ ] **Step 2: File follow-up issues:**
  - fngogen: align status codes with the host denial contract (401 vs 403).
  - fnnodejsgen: `x-entitlement-binding` placeholder parity.
  - host-manager: should gate-bypassing tokens (exchanged FAT, client_credentials `resource`) carry the `functions:<basePath>:read` identity check?
- [ ] **Step 3: Comment on fngogen#18** with the commit range and the follow-up links.

### Task 4b: fngogen: generated functions require entitlements/go ≥ v0.7.0

Added 2026-11-01 at the user's request: the fngogen release ships with entitlements v0.7.0. v0.7.0's Go API is call-compatible with what the template uses (`NewEntitlementsChecker`, `ParseRequirements`, `ParseEntitlements`, `BindRequirements`, `VerifyParsedEntitlements`).

**Files:**
- Modify: `entry-point.sh`. After `go mod tidy`, raise `github.com/kdex-tech/entitlements/go` to `v0.7.0` when the module's current version is lower (`go list -m -f '{{.Version}}' github.com/kdex-tech/entitlements/go`, compared semver-aware). **Never downgrade** a module that already requires a newer version. Then run `go mod tidy` again.
- Modify: `cmd/main_test.go` `generateFixture`. Mirror the same raise, so the probes run against what entry-point produces.
- Test: `cmd/main_test.go`.

**Interfaces:** none new. Add the floor as one named value in `entry-point.sh` (`ENTITLEMENTS_MIN_VERSION=v0.7.0`) with a comment saying why, and mirror it as one named value in the test helper.

- [ ] **Step 1: Write the failing test `TestGenerate_RaisesEntitlementsToFloor`.** In `generateFixture`'s flow, pre-seed the work dir's module with `require github.com/kdex-tech/entitlements/go v0.6.0` before generation. Generate the bearer fixture. Assert that `go list -m -f '{{.Version}}' github.com/kdex-tech/entitlements/go` prints `v0.7.0`.
- [ ] **Step 2: Write `TestGenerate_KeepsEntitlementsAtFloor`.** Same, pre-seeded with `v0.7.0`: it stays `v0.7.0`. The never-downgrade branch, a version above the floor, cannot be exercised with a real module until a newer release exists. Implement the comparison with `sort -V` in entry-point.sh, and state that in a comment.
- [ ] **Step 3: Run** `cd cmd && go test . -run 'TestGenerate_(Raises|Keeps)Entitlements' -count=1`. Expected: Raises FAILS (stays at v0.6.0), Keeps passes.
- [ ] **Step 4: Implement** the entry-point.sh and generateFixture changes.
- [ ] **Step 5: Run** the two tests plus `TestGenerate_BearerBindsRequirementPlaceholders`, then `GOTOOLCHAIN=go1.26.0 make lint`. Expected: PASS and `0 issues.`
- [ ] **Step 6: Commit** `build: generated functions require entitlements/go v0.7.0`
