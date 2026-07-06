# SIG Security Tooling introduction (draft — post under your own identity)

**Where to post** (verified 2026-07-07; re-check links the day you post):

- Slack: `#sig-security-tooling` on slack.k8s.io (subproject: "Development
  and Enhancements of Security Tooling", kubernetes/sig-security)
- Mailing list: `kubernetes-sig-security` (Google Group) — joining adds the
  meeting invites to your calendar
- SIG Security meeting: biweekly Fridays 8:00 PT — agenda doc is linked from
  kubernetes.dev/community/community-groups/sigs/security/

**Suggested flow:** join the mailing list first, post the intro there, drop a
short version in Slack the same day, then bring the Kyverno policy PRs to a
meeting once they're up.

---

## Draft (mailing list / Slack long-form)

Subject: Argus — contextual risk scoring for cluster findings; two policy
gaps we'd like to upstream

Hi all,

I'm Vamshi Krishna Santhapuri — infrastructure security architect, 14+ years
of Linux and Kubernetes operations work. I've been building Argus
(github.com/rrskris/Argus), an Apache-2.0 cluster security scanner, and I'd
rather grow it with this group's visibility than in isolation.

The problem Argus works on is not detection — kube-bench, Trivy, Kubescape
and friends detect plenty. The problem is that every scanner ranks findings
by flat severity, so a wildcard ClusterRole in a throwaway dev cluster looks
exactly as urgent as the same one in an internet-facing PCI production
cluster. Argus scores each finding through an explainable formula (base
severity × environment × data classification × compliance scope × exposure)
and attaches a remediation object to every finding: the fix command, why it
ranks where it does, the CIS Kubernetes Benchmark v1.12.0 control it maps to,
and an audit-trail note. Detection without that guidance is how alert fatigue
happens.

Current state: CVE scanning (Kubernetes official feed / OSV / NVD) matched
against live cluster and add-on versions, and RBAC misconfiguration scanning
covering the CIS 5.1.x controls that are inspectable from Role/Binding state
— wildcards, secrets access, exec grants, escalate/bind/impersonate,
nodes/proxy, CSR approval, webhook config writes, token creation, and
cluster-admin bound to broad identities.

Two things came out of building the RBAC rules that seem worth bringing
here, since they're gaps in the shared ecosystem rather than in Argus:

1. The Kyverno policy library blocks pod exec *requests* at admission
   (block-pod-exec-by-*), but nothing restricts the RBAC *grant* of
   pods/exec, pods/attach, or pods/portforward in a Role/ClusterRole — the
   standing permission itself. We wrote that policy following the
   restrict-clusterrole-nodesproxy conventions and would like to PR it.

2. restrict-binding-system-groups covers system:anonymous,
   system:unauthenticated, and system:masters — but not
   system:authenticated, which is strictly broader than most of those. A
   one-rule addition covers it.

If there's a better home or prior art for either, I'd genuinely like to know
before submitting. And if contextual scoring of findings overlaps with
anything this group is already thinking about (PolicyReport consumers,
severity normalization, etc.), I'd be glad to align with it rather than
invent another format — Argus already plans to ingest PolicyReports rather
than define its own policy engine.

I'll be at an upcoming Friday meeting. Feedback, criticism, and "this
already exists, look here" all welcome.

Vamshi
github.com/rrskris/Argus | linuxcent.com

---

## Short version (Slack)

Hi all — Vamshi, infra security architect, 14y Linux/K8s ops. Building Argus
(github.com/rrskris/Argus, Apache-2.0): cluster CVE + RBAC scanning where
every finding gets an explainable contextual risk score (env × data class ×
compliance × exposure) and a remediation object with CIS v1.12.0 mappings —
aimed at the "every scanner ranks by flat severity" problem. Building the
RBAC rules surfaced two gaps in the Kyverno policy library we'd like to
upstream: no policy restricts RBAC *grants* of pods/exec|attach|portforward
(only exec requests), and restrict-binding-system-groups misses
system:authenticated. Posted details on the mailing list — feedback welcome
before I open the PRs.
