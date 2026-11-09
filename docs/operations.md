[← OVLM home](../README.md)

# Operations: alerts and paging

| Field | Value |
|---|---|
| Status | **Implemented, not lab validated.** The rule file is checked against the code by `tests/unit/test_alert_rules.py` (metric and label names, `promtool check rules`, `promtool test rules`). No deployment has paged from it yet. |
| Audience | Whoever runs OVLM and is on call for it |
| Rule file | [`deploy/prometheus/ovlm-alerts.yml`](../deploy/prometheus/ovlm-alerts.yml) (unit tests: [`ovlm-alerts.test.yml`](../deploy/prometheus/ovlm-alerts.test.yml)) |
| Last updated | 2026-11-09 |

> [!IMPORTANT]
> **Paging is mandatory** ([architecture.md §6](architecture.md#6-observability)). A deployment must route at least
> `OvlmPostStartFailure` and `OvlmNeedsHumanInWindow` to an on-call pager. After a failure past the service start
> on green (D-1 = B, [renewal-workflow.md §4.1](renewal-workflow.md#41-automatic-restore-in-the-window--closed-table-sec-r-30-sre-q5))
> the service stays down until a human acts. OVLM has no notification channel of its own yet (V1, SRE-R-20): these
> alerts are the paging path.

## 1. Scrape OVLM

The api and the worker each serve `/metrics` on their internal listener (`http.metrics_port`, default `9100`), never on
the public port (SEC-R-17). In the Compose stack that listener is reachable on the Compose network only. Run
Prometheus on that network (or behind an authenticating proxy) and scrape both with these job names, which the rules
assume:

```yaml
# prometheus.yml (excerpt)
rule_files:
  - /etc/prometheus/rules/ovlm-alerts.yml
scrape_configs:
  - job_name: ovlm-api
    static_configs: [{targets: ["api:9100"]}]
  - job_name: ovlm-worker
    static_configs: [{targets: ["worker:9100"]}]   # one target per worker
alerting:
  alertmanagers:
    - static_configs: [{targets: ["alertmanager:9093"]}]
```

One way to put Prometheus on the Compose network is a site file of your own (not shipped) listed after the
production file, `COMPOSE_FILE=compose.prod.yaml:compose.site.yaml` in `.env`, with a `prometheus` service that mounts `deploy/prometheus/` read-only at
`/etc/prometheus/rules/`. Do not publish the metrics ports to get them scraped.

Load or reload the rules:

```bash
promtool check rules deploy/prometheus/ovlm-alerts.yml        # read-only syntax and expression check
promtool test rules deploy/prometheus/ovlm-alerts.test.yml    # read-only rule unit tests
curl -X POST http://prometheus:9090/-/reload                  # needs --web.enable-lifecycle; or send SIGHUP
```

Copy the file with each release: alerts and metric names change together, and the unit test only guards the copy in
the repository. Thresholds marked `tune` in the file are defaults; keep them in step with `admission.after`,
`signal.after`, `worker.heartbeat_interval` and your policies' `max_window_duration`.

Every alert has a `severity` label (`page` or `ticket`) and a `runbook_url` annotation pointing to its section below.

Backups, restores and upgrades of OVLM itself, and when they are refused (never mid-window):
[backup-restore-upgrade.md](backup-restore-upgrade.md).

## 2. Route pages (Alertmanager)

```yaml
# alertmanager.yml (excerpt)
route:
  receiver: ovlm-tickets
  group_by: [alertname]
  routes:
    - matchers: ['severity="page"', 'alertname=~"Ovlm.*"']
      receiver: oncall-pager
      group_wait: 0s          # a window is open: do not batch
      repeat_interval: 30m
    - matchers: ['severity="ticket"', 'alertname=~"Ovlm.*"']
      receiver: ovlm-tickets
      repeat_interval: 24h
receivers:
  - name: oncall-pager
    pagerduty_configs:
      - routing_key_file: /etc/alertmanager/secrets/pagerduty_routing_key
  - name: ovlm-tickets
    webhook_configs:
      - url: https://tickets.example.internal/hooks/ovlm
```

Any pager integration works (PagerDuty, Opsgenie, a phone gateway). Test the path before the first renewal: fire a
test alert with `amtool alert add OvlmPostStartFailure severity=page` and check that the on-call phone rings.

## 3. Alert list

| Alert | Severity | Fires when | Metric |
|---|---|---|---|
| [OvlmPostStartFailure](#ovlmpoststartfailure) | page | a run is in needs_human with `reason=post_start_failure`, or a post-start failure happened in the last 30 min | `ovlm_runs_needing_attention`, `ovlm_post_start_failures_total` |
| [OvlmNeedsHumanInWindow](#ovlmneedshumaninwindow) | page | a run is in needs_human with `phase=window` | `ovlm_runs_needing_attention` |
| [OvlmApprovalEvidenceInvalidInWindow](#ovlmapprovalevidenceinvalidinwindow) | page | needs_human `reason=approval_evidence_invalid` while `phase=window` (SRE-R-23) | `ovlm_runs_needing_attention` |
| [OvlmWindowBudgetExceeded](#ovlmwindowbudgetexceeded) | page | a window ran past `max_window_duration` in the last 30 min | `ovlm_window_budget_exceeded_total` |
| [OvlmRestoreDowntimeOpenTooLong](#ovlmrestoredowntimeopentoolong) | page | a restore downtime interval has been open > 30 min | `ovlm_renewal_downtime_open_seconds{kind="restore"}` |
| [OvlmWorkerDown](#ovlmworkerdown) | page | no worker target is up for 5 min | `up{job="ovlm-worker"}` |
| [OvlmWorkerHeartbeatStale](#ovlmworkerheartbeatstale) | page | a worker loop has not beaten for > 60 s, for 2 min | `ovlm_worker_heartbeat_age_seconds` |
| [OvlmRunNeedsHumanLong](#ovlmrunneedshumanlong) | ticket | runs in needs_human for 15 min (any phase) | `ovlm_runs_needing_attention` |
| [OvlmApprovalEvidenceInvalid](#ovlmapprovalevidenceinvalid) | ticket | an approval evidence re-validation failed (any gate) | `ovlm_approval_evidence_invalid_total` |
| [OvlmFencedCommitRejected](#ovlmfencedcommitrejected) | ticket | a fenced write matched 0 rows | `ovlm_fenced_commit_rejected_total` |
| [OvlmLeaseTakeover](#ovlmleasetakeover) | ticket | a step was taken over after its lease expired | `ovlm_lease_takeovers_total` |
| [OvlmRunRequestedOverdue](#ovlmrunrequestedoverdue) | ticket | a run waits in `requested` longer than `admission.after` (SRE-R-25) | `ovlm_runs_requested_overdue` |
| [OvlmRunSignalPendingOverdue](#ovlmrunsignalpendingoverdue) | ticket | a `run_signal` is unconsumed after `signal.after` (SRE-R-24) | `ovlm_run_signals_pending_overdue` |
| [OvlmStepAccepted](#ovlmstepaccepted) | ticket | an approver used accept-step (ADR-0008) | `ovlm_step_accepted_total` |
| [OvlmAutoRestore](#ovlmautorestore) | ticket | OVLM restored a window automatically | `ovlm_auto_restore_total` |
| [OvlmCredentialExpiring](#ovlmcredentialexpiring) | ticket | an application credential is expired or expires within 7 days | `ovlm_credentials_expiring` |
| [OvlmCredentialValidationFailing](#ovlmcredentialvalidationfailing) | ticket | an active credential failed its last validation | `ovlm_credentials_failing_validation` |

Every metric is listed in [architecture.md §6](architecture.md#6-observability).

## 4. Runbooks

Common first steps for every renewal alert:

1. Open the run in the UI (**Runs**, filter `needs_human`) or `GET /api/v1/runs/{id}`. Read `needs_human_reason`,
   `phase`, the current step and `available_actions[]`: each action states its concrete effect from the current state
   ([renewal-workflow.md §6.1](renewal-workflow.md#61-operator-view-at-3-am-sre-r-9)).
2. Refresh the current-truth panel with **Probe** (`POST /runs/{id}/actions/probe`, read-only, no confirmation).
3. Do not change servers, volumes or the floating IP by hand while OVLM holds the run's locks. If an OpenStack admin
   must act ([renewal-workflow.md §6](renewal-workflow.md#6-states-that-need-an-openstack-admin)), record it afterwards
   with `mark-resolved`.

The operator actions are described in [renewal-workflow.md](renewal-workflow.md) (§4 restore, §5 interruption, §6
admin states) and [api-design.md](api-design.md): `retry-step` (operator; a new attempt starts with a probe),
`rollback` (operator + typed confirmation; in the window: the restore sequence), `revert` (after the cutover),
`mark-resolved`, `reprepare-automation` (approver + step-up; one re-clone of the pinned commit) and `accept-step`
(approver + step-up; S2 only, [ADR-0008](decisions/ADR-0008-accept-step-restore-exit.md)).

### OvlmPostStartFailure

**Means:** a renewal failed at W7–W10 (service start on green, health check, floating IP move, external check), or the
window budget or the approval evidence check failed after W7, and no W4 snapshot exists. OVLM stopped in
`needs_human` and keeps all locks. The service is probably down: blue is stopped, the data volume is on green, and
green may have written to it.

**First checks:** the failed step and its error (run page, step attempts); the current-truth panel after **Probe**:
is green running, is the volume mounted on green, where is the floating IP? Is the external health check failing
because of green or because of the network?

**Act:**
- Transient cause (API hiccup, slow service start) and green looks right: `retry-step`.
- Green is broken: `rollback`. Read its effect text first: "blue will start on data the new VM may have changed; no
  snapshot exists". Accept that only if the data written by green is acceptable for blue.
- Data must not go back to blue: fix green by hand (the run keeps its locks), then `mark-resolved` with what was done.
- The rollback stops at S2 because the quiesce playbook refuses on green: see [OvlmRestoreDowntimeOpenTooLong](#ovlmrestoredowntimeopentoolong).

### OvlmNeedsHumanInWindow

**Means:** a run stopped inside the downtime window (W1–W10). The service is down or moving. The alert's `reason`
label is the park reason.

**First checks:** `reason` and the step; **Probe**; how much of the window budget is left (run page: worst-case window
and budget).

**Act, by reason:**
- `post_start_failure`: see [OvlmPostStartFailure](#ovlmpoststartfailure).
- `approval_evidence_invalid`: see [OvlmApprovalEvidenceInvalidInWindow](#ovlmapprovalevidenceinvalidinwindow).
- `window_budget_exceeded`: see [OvlmWindowBudgetExceeded](#ovlmwindowbudgetexceeded).
- `api_unreachable`: OpenStack was unreachable; OVLM re-probes and may resume or restore by itself
  ([renewal-workflow.md §5.1](renewal-workflow.md#51-self-resolution-of-api_unreachable-sec-r-34-sre-r-26)). If the API
  is back and the run is still parked, choose `retry-step` or `rollback`.
- `automation_checkout_lost` / `automation_checkout_unverifiable`: the worker lost the verified playbook checkout;
  an approver runs `reprepare-automation`, then `retry-step` ([renewal-workflow.md §5](renewal-workflow.md#5-interruption-and-resume)).
- Stuck volume, admin lock, compute host down: an OpenStack admin acts
  ([renewal-workflow.md §6](renewal-workflow.md#6-states-that-need-an-openstack-admin)), then `mark-resolved`.
- Data phases (W1 quiesce, W6 data attach): read the attached `findmnt` evidence before `retry-step`.
- Anything unclear and still before W7: `rollback` restores blue with no data risk.

### OvlmApprovalEvidenceInvalidInWindow

**Means:** the worker re-validated the G2 approval evidence inside the window and it did not match (approver,
signature, scope or expiry; [renewal-workflow.md §3.1](renewal-workflow.md#31-approval-evidence-re-validated-by-the-worker-sec-r-1-sec-r-2)).
This can be a forged or tampered approval. OVLM stopped; nothing proceeds under that approval.

**First checks:** the security audit events of the run (`approval_evidence_invalid`, gate); who approved and when;
recent changes to users, roles or the database.

**Act:** treat it as a security incident and as a stopped window. Restore the service with `rollback` (it does not need
the invalid approval to continue forward). Do not `retry-step` until the security review is done. If the failure
happened after W7, [OvlmPostStartFailure](#ovlmpoststartfailure) applies to the rollback decision as well.

### OvlmWindowBudgetExceeded

**Means:** a window ran longer than the `max_window_duration` the approver saw. Before W7 OVLM restores automatically
when the closed table allows it; after the service start it stops (D-1 = B).

**First checks:** did an automatic restore start (`OvlmAutoRestore`, run page)? Which step was slow, and why (OpenStack
latency, a slow playbook)?

**Act:** restore running: watch it finish (S9 closes the downtime). Run parked: as for
[OvlmNeedsHumanInWindow](#ovlmneedshumaninwindow). Afterwards, fix the policy budget or the slow step before the next
renewal.

### OvlmRestoreDowntimeOpenTooLong

**Means:** a restore downtime interval (S2 to S9 of a rollback or revert) has been open for more than 30 minutes: blue
is not serving again yet. The run is usually parked in a restore step.

**First checks:** the restore step and its reason; **Probe**. Is S2 `quiesce_green` parked because its playbook refused
on green?

**Act:**
- S2 parked after its playbook ran and refused, and the probe shows green is already quiesced (volume not mounted,
  units inactive): an approver uses `accept-step` with a fresh probe and an attestation
  ([ADR-0008](decisions/ADR-0008-accept-step-restore-exit.md)).
- Checkout lost: `reprepare-automation`, then `retry-step`.
- Transient error: `retry-step`. Stuck OpenStack resource: an admin acts, then `mark-resolved`.

### OvlmWorkerDown

**Means:** Prometheus scrapes no worker. Nothing runs: no step, no window, no restore, no admission.

**First checks:** `docker compose ps worker`, `docker compose logs --tail=200 worker`: a refused start (schema not at
head, KEK mismatch), crash loop, out of memory? Is Prometheus itself on the Compose network?

**Act:** fix and restart the worker. Running steps keep their lease until expiry; the restarted worker takes them over
with a probe first ([renewal-workflow.md §5](renewal-workflow.md#5-interruption-and-resume)). Check every run that was
in the window when it went down.

### OvlmWorkerHeartbeatStale

**Means:** the worker process answers scrapes but its main loop has not beaten (hung, paused, swap storm). Its leases
expire; another worker (if any) takes the steps over after `worker.takeover_delay`.

**First checks:** the worker's logs and resource use; the database connection (`ovlm_worker_db_reachable`).

**Act:** restart the stuck worker (`docker compose restart worker`). The fence gate stops a paused worker from
committing late (ADR-0003). Check runs that were in the window.

### OvlmRunNeedsHumanLong

**Means:** runs have been in needs_human for more than 15 minutes (any phase). Outside the window no service is down,
but locks are held and the renewal is stuck.

**Act:** open the runs (labels `phase` and `reason`) and choose `retry-step`, `rollback`/abort, `mark-resolved` or
`reprepare-automation` as the run page offers.

### OvlmApprovalEvidenceInvalid

**Means:** approval evidence failed re-validation at gate `gate` (any phase). Outside the window the run stopped before
any downtime.

**Act:** security review as in [OvlmApprovalEvidenceInvalidInWindow](#ovlmapprovalevidenceinvalidinwindow); then
discard the run or request a new approval.

### OvlmFencedCommitRejected

**Means:** a worker tried to commit a step it no longer owned (lease lost: pause, DB outage, takeover). The commit was
refused, as designed (ADR-0003).

**Act:** find the cause (worker logs around the time, DB availability, host pauses). Repeated: check
`worker.lease_duration` against real step durations. Check the affected run continued correctly.

### OvlmLeaseTakeover

**Means:** a running step's lease expired and a worker claimed it again (crash, kill, pause).

**Act:** find why the first worker stopped. Check the run: window and destructive steps re-probe before acting.

### OvlmRunRequestedOverdue

**Means:** a run waits for admission longer than `admission.after`: no worker is admitting (down, draining, slots full).

**Act:** check workers (`ovlm_workflow_live_workers`, [OvlmWorkerDown](#ovlmworkerdown)) and concurrency limits.

### OvlmRunSignalPendingOverdue

**Means:** an operator action (abort, rollback, ...) has not been consumed after `signal.after`. The run page shows
"signal pending".

**Act:** check that workers are running. A pending rollback during a window is urgent: treat it as
[OvlmWorkerDown](#ovlmworkerdown).

### OvlmStepAccepted

**Means:** an approver closed a restore step (S2) without running its playbook (accept-step, ADR-0008). Expected to be
rare.

**Act:** review the run's `accepted_steps[]`: approver, attestation, probe evidence. Fix the playbook or the guest so
the next restore does not need it.

### OvlmAutoRestore

**Means:** OVLM restored a window automatically (trigger label: failed step class, budget, evidence, API outage). The
service is back on blue; the renewal did not happen.

**Act:** read the failed step and fix the cause before a new renewal. The W4 snapshot, if any, is kept as a manual way
back.

### OvlmCredentialExpiring

**Means:** a Keystone application credential is expired or expires within 7 days. Runs that need it will be refused.

**Act:** create a new application credential and upload it ([install-guide.md §6](install-guide.md#6-create-the-two-keystone-application-credentials),
[credential-store.md](credential-store.md)).

### OvlmCredentialValidationFailing

**Means:** an active credential failed its last read-only Keystone validation; no new run uses it.

**Act:** check the worker log line of the validation job (it names the credential), the Keystone endpoint and the
credential's roles; replace the credential if it was revoked.
