# Ledger Forge: V2-only Attack & Defense

This challenge uses the persistent GZCTF V2 checker contract. The flag is an
ordinary private ledger memo, stored and read through the service API as its
legitimate owner. The checker never exploits JWT algorithm confusion or SSTI,
forges tokens, or reads a privileged `/flag` endpoint. The intentionally
vulnerable service remains patchable; exploit success is not an SLA requirement.

## What defenders must preserve

- Ordinary customers can register, log in, add private entries, list their own
  entries, fetch their profile, and fetch the public signing key.
- Existing accounts and entries survive an application restart. Preserve the
  directory configured by `LEDGER_DATA_DIR` (default `/app/data`), including `ledger.sqlite3` and the
  signing key. Replacing or deleting this data destroys retained flags.
- Entry `clientId` is an opaque, per-owner idempotency key. Repeating creation
  must not change an accepted memo, duplicate it, or resurrect a deleted record.
- Patch token verification and unsafe template execution while keeping normal
  application functionality. The checker uses genuine server-issued RS256
  tokens and never requires user-supplied templates to execute as code.

There is no hidden rule requiring a vulnerability to remain exploitable.
Missing retained data is a retention failure, not evidence that a patch is bad.
Preserving legitimate access and stored data keeps the checker healthy.

## Checker flow

The image starts one long-lived HTTP process on port 8081. Every authenticated
`POST /check` runs these hooks from `checker/checks.py`:

1. Ordinary functionality checks: health, public key, register, login,
   create/list a harmless expense, and authenticated profile.
2. `put_flag(target, flag)` only for a newly issued flag with platform permission
   to initialize it. This registers a private customer and stores one memo.
3. `get_flag(target, flag)` for **every still-valid flag**, using its owner's
   normal login and entry-listing endpoints. The framework compares the actual
   returned memo with the expected value; retrieval never creates anything.

The flag's complete secret value derives domain-separated account credentials
and its opaque entry key. They cannot be guessed from team IDs or tick numbers.
A replacement worker reconstructs those credentials; it does not need local
state or a volume. Flags, credentials, and target response bodies are not logged.

The platform's database, **not the worker filesystem or the team's service**,
owns whether placement has been attempted. Every requested flag includes:

| `placement` | Worker behavior |
| --- | --- |
| `new` | Only the current tick's new flag may be initialized once. |
| `confirmed` | Read only; missing or corrupt data is negative retention evidence. |
| `failed` | Read only; a previous explicit placement failure must not be repaired. |
| `unknown` | Read only; successful retrieval resolves the ambiguity, while missing data produces `InternalError`, not an invented retention verdict. |

Results include `id`, `retrievable`, and `placement` (`confirmed`, `failed`, or
`unknown`) for every flag. The top-level status describes functionality; GZCTF
derives `Recovering` when old flags are missing and `Mumble` when the newest
flag is missing. An unresolved placement/worker error is `InternalError`.
Unknown writes are never retried blindly or silently scored as a team failure.

`GET /healthz` advertises both `protocolVersion: 2` and
`flagPlacement: "platform-v1"`. `GZCTF_CHECKER_TOKEN` is mandatory; callers send
it in `X-GZCTF-Checker-Token`. V1 requests and missing placement metadata are
rejected. Rebuild **both the service image and checker image** when deploying
this change. An older V2 checker that does not advertise `platform-v1` is no
longer ready even if it advertises `protocolVersion: 2`.
New games begin with fresh platform-owned placement history.

## Local regression tests

Install both `checker/requirements.txt` and `src/requirements.txt` in a Python
environment, then run:

```sh
cd checker
python3 -m unittest -v test_checker.py
```

Tests use temporary local service/database instances and the actual persistent
HTTP worker. They cover retained flags, a safely patched JWT/SSTI reference,
deletion/corruption, retry without repair, checker replacement, service restart,
ambiguous writes, and strict authenticated V2 requests. No running game,
external target, container, or Kubernetes resource is changed.

Application restarts keep the configured data directory. If an organizer
replaces an entire target container/pod, its data directory must also be
preserved with the chosen storage setup; a completely fresh filesystem is a
service reset, not a data-preserving code patch.
