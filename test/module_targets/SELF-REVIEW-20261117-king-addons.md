# King Addons fixture review, 2026-11-17

## Summary

Qualified one owner on ten recorded profiles and 36 public cases. The reporting
repair is isolated; nine passing traces retain 23c9092b5aa and the root assertion
repair is replayed at 3066fd30e18. The broader campaign remains active; no PR.

## What looks good

Independent genuine vendor/widget/password/role/upload/execution controls separate
setup failures, a real reporting defect and an incorrect fixture expectation.
The same five-case adapter changes only owner bytes among 94 inputs and goes from
four reporting failures to zero. Seventeen typed sessions, thirteen successful
scoped credential/login pairs, repeats, two Subscriber permission negatives,
missing nonces, disabled registration and wrong-password rejection pass. Selected
state remains strict. Inputs rehash from their recorded commits; human Scenarios
are byte-identical. Resource caps and all 50 attached-resource removals are verified.

## Concerns

No unresolved concern blocks the covered paths. Nine profiles retain their earlier
fixture revision with a reviewed root-only assertion delta; no all-green 36-case
aggregate is claimed. Passive findings do not prove exploitation, including when
registration is disabled. Explicit stdapi/Unix success does not qualify staged
PHP, defaults, Windows or other deployments. Selected-state restoration is not a
whole-database restore; cached payload bytes are not an independent ZIP capture.
Prior native CI executes an upstream checkout and has an unresolved transport
failure; it cannot be used as fork exact-revision validation.

## Suggestions

Retain the failed evidence and deferred ledger. Continue with the source-prepared
SureTriggers candidate after publication and cleanup; its four archives/CNA/SVN
comparisons establish source readiness only, with no native or module calls yet.
