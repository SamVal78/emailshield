# Splunk integration

EmailShield verdicts land in the same Splunk instance as SentinelLab's detections,
so the two projects can be queried together. The cross-project search at the bottom
of this page is the reason to bother.

Every field here comes from `tools/splunk_export.py`. Nothing in this document
requires a Splunk licence beyond the free local one.

---

## Export

```bash
cd ~/Projects/emailshield
source .venv/bin/activate
python3 tools/splunk_export.py --out out/emailshield_alerts.json
```

Only interesting verdicts:

```bash
python3 tools/splunk_export.py --min-action investigate --out out/emailshield_alerts.json
```

One JSON object per line. Evidence strings are included, unlike the dataset produced
by `tools/ingest_real.py`, because this output is local and meant to be read.

---

## Ingest

Splunk web UI at `http://localhost:8000`:

1. **Settings → Add Data → Upload**
2. Select `out/emailshield_alerts.json`
3. Source type: **`_json`**, then override the name to `emailshield:alert`
4. Index: `sentinellab`, or create `emailshield` if you would rather keep them apart
5. Review, Submit

The `timestamp` field is analysis time in ISO 8601 and Splunk picks it up
automatically. Note it is deliberately *not* the message `Date` header, which is
attacker-controlled and carried separately as `claimed_date`.

**Set the time range to All time** before running any of these searches.

---

## Searches

### 1. Triage queue, worst first

```
index=sentinellab sourcetype="emailshield:alert"
| eval priority = case(
      action=="escalate", 1,
      action=="quarantine", 2,
      action=="investigate", 3,
      true(), 4)
| sort priority, - score
| table _time, action, score, confidence, requires_human_approval,
        from_address, subject, signals_fired
```

### 2. Verdicts needing human approval before they apply

The operationally important queue. These are messages the tool wants to quarantine
or escalate on evidence that is not high confidence, and the asymmetry of costs
means a person should look first.

```
index=sentinellab sourcetype="emailshield:alert" requires_human_approval=true
| table _time, action, score, confidence, from_address, subject
| sort - score
```

### 3. Which signals actually fire, and how strong they are

The operational version of the ablation study. If a signal never appears here, it is
contributing nothing to this mail flow.

```
index=sentinellab sourcetype="emailshield:alert"
| spath findings{} output=finding
| mvexpand finding
| spath input=finding
| stats count AS occurrences,
        avg(weight) AS mean_weight,
        values(confidence) AS confidences
        BY signal_id, title
| eval mean_weight = round(mean_weight, 1)
| sort - occurrences
```

### 4. Sender domains by worst verdict

```
index=sentinellab sourcetype="emailshield:alert"
| stats count AS messages,
        max(score) AS worst_score,
        values(action) AS actions
        BY from_domain
| where worst_score >= 25
| sort - worst_score
```

### 5. Repeated campaign: one lure sent to many recipients

A single verdict is one message. The same subject and sending domain across several
recipients is a campaign, and EmailShield alone cannot see that because it scores one
message at a time.

```
index=sentinellab sourcetype="emailshield:alert"
| stats dc(recipients) AS recipients_hit,
        count AS messages,
        max(score) AS worst_score
        BY from_domain, subject
| where messages > 1 OR recipients_hit > 1
| sort - recipients_hit, - worst_score
```

### 6. Cross-project correlation, phishing to account takeover

The search that justifies putting both projects in one index.

SentinelLab's `SL-IDP-003` fires on a successful login from an unusual country or
device. EmailShield fires on a credential-harvesting email. Neither is conclusive
alone. An email to a user followed within a few hours by an anomalous login *by that
user* is a chain, and the order matters: lure first, then compromise.

```
index=sentinellab (sourcetype="emailshield:alert" OR sourcetype="_json")
| eval user = coalesce(mvindex(recipients, 0), entity, username)
| eval user = lower(replace(user, "@.*$", ""))
| eval evidence_type = if(sourcetype=="emailshield:alert", "email", "identity")
| where isnotnull(user) AND user!=""
| sort 0 user, _time
| streamstats current=f last(_time) AS prior_email_time,
              last(action) AS prior_email_action,
              last(score) AS prior_email_score
              BY user
| where evidence_type=="identity" AND isnotnull(prior_email_time)
| eval gap_minutes = round((_time - prior_email_time) / 60, 1)
| where gap_minutes >= 0 AND gap_minutes <= 480
| table user, gap_minutes, prior_email_action, prior_email_score, rule_id, severity
| sort gap_minutes
```

**Read the caveats before quoting this one.** The user extraction depends on the
recipient local part matching the identity username, which holds in the synthetic
data and would need a proper identity lookup in reality. The eight-hour window is a
guess, not a calibrated figure. And correlation in time is not causation: two events
eight minutes apart may be one intrusion or two unrelated things, which is exactly
the point made in SentinelLab's network case study. State which, and on what basis.

---

## Dashboard panels

Add to the existing `SentinelLab Detections` dashboard, or make a new
`EmailShield Triage` one.

| Panel | Search | Visualisation |
|---|---|---|
| Verdicts by action | `... \| stats count BY action` | Pie |
| Score distribution | `... \| stats count BY score \| sort score` | Column |
| Signal frequency | search 3 above | Bar |
| Awaiting human approval | search 2 above | Table |
| Verdicts over time | `... \| timechart span=1d count BY action` | Line |

---

## Field reference

| Field | Meaning |
|---|---|
| `action` | allow, investigate, quarantine, escalate |
| `score` | Total weight after credits and suppression |
| `confidence` | Quality of the evidence, independent of score |
| `requires_human_approval` | True when impact exceeds evidence quality |
| `decisive_finding_count` | Findings that raised the action floor regardless of score |
| `signals_fired` / `signals_silent` | Which of the six produced findings, and which were checked and found nothing |
| `claimed_date` | The `Date` header. Attacker-controlled, never used as `_time` |
| `findings{}` | Nested: signal id, title, weight, confidence, MITRE, evidence |

`signals_silent` is worth keeping. An analyst needs to know what was checked and
found nothing, not only what fired, and an absent check and a passed check look
identical if you only log the hits.
