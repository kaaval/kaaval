# Upstream contributions ledger

Every contribution Kaaval's maintainers make to upstream projects, newest first.
This is both a community-credibility record (CNCF Sandbox applications ask for
evidence of ecosystem participation) and the source list for build-in-public
content.

| Date | Project | Contribution | Status |
|---|---|---|---|
| 2026-07-11 | [kyverno/policies](https://github.com/kyverno/policies) | [#1508](https://github.com/kyverno/policies/pull/1508) — block `system:authenticated` in `restrict-binding-system-groups` (all three variants + tests) | 🟡 in review |
| 2026-07-11 | [kyverno/policies](https://github.com/kyverno/policies) | [#1507](https://github.com/kyverno/policies/pull/1507) — new `restrict-exec-verbs-roles` policy (blocks RBAC *grants* of pods/exec\|attach\|portforward) | 🟡 in review |

## Why these projects

Kaaval detects Kubernetes security misconfigurations; the same research that
produces our detection rules regularly uncovers gaps in the ecosystem's
admission-policy libraries. Contributing those fixes upstream is the point —
prevention belongs at admission, detection-with-context is Kaaval's job, and
the two compose. See [`policies/kyverno/README.md`](../policies/kyverno/README.md)
for the full coverage map.

## Engagement notes

- Review responses within 24h (async — no meeting commitments before H1 2027).
- Next targets: Kubernetes SIG Security tooling (async), Kubescape
  (reachability overlap, H1 2027), Falco/OPA (with the runtime phase, 2027+).
