# crowdsec-o11y

Grafana observability stack for [CrowdSec](https://crowdsec.net) — dashboards, alert rules, and a Grafana Alloy scrape module.

## Contents

```
crowdsec-o11y/
├── alloy/modules/crowdsec.alloy          # Grafana Alloy scrape module
├── dashboards/
│   ├── crowdsec-overview.json            # Security overview + engine health
│   └── crowdsec-log-processing.json      # Pipeline analysis + detection efficiency
├── alerts/
│   └── crowdsec-alerts.yaml              # 7 Grafana alert rules
└── blog/
    └── crowdsec-grafana-observability.md # Writeup covering the full setup
```

## Alloy Module

The scrape module collects CrowdSec's Prometheus metrics endpoint (port 6060) and forwards them to a remote write destination. Deploy it with [Grafana Alloy](https://grafana.com/docs/alloy/latest/) using `import.git`:

```alloy
import.git "o11y_crowdsec" {
  repository = "git@github.com:colinedwardwood/crowdsec-o11y.git"
  path       = "alloy/modules/crowdsec.alloy"
  revision   = "main"
}

o11y_crowdsec.crowdsec "default" {}
```

Required environment variables on the host:

| Variable | Description |
|---|---|
| `GCLOUD_PROM_ENDPOINT` | Grafana Cloud Prometheus remote_write URL |
| `GCLOUD_PROM_USERNAME` | Grafana Cloud metrics username |
| `GCLOUD_RW_API_KEY` | Grafana Cloud read/write API key |
| `GCLOUD_LOKI_ENDPOINT` | Grafana Cloud Loki push URL |
| `GCLOUD_LOKI_USERNAME` | Grafana Cloud logs username |

## Dashboards

Import via Grafana UI (**Dashboards → Import → Upload JSON**) or the provisioning API. Both dashboards use a `DS_PROMETHEUS` input variable — map it to your Prometheus datasource on import.

**crowdsec-overview** — operational view: active decisions, bouncer health, alert rate by scenario, LAPI activity, engine health stats.

**crowdsec-log-processing** — pipeline view: parser hit rates by source, parse success/failure breakdown, bucket activity, detection efficiency by scenario.

## Alert Rules

The `crowdsec-alerts.yaml` file is in Grafana's native provisioning format. Import via the API:

```bash
curl -X POST \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/yaml" \
  --data-binary @alerts/crowdsec-alerts.yaml \
  https://<your-grafana>/api/v1/provisioning/alert-rules/export
```

Seven rules covering:
- **Service Down** — fires when the metrics endpoint disappears (2m)
- **Parser Failure Rate High** — silent log source blind spot (5m)
- **LAPI Error Rate High** — LAPI unreachable (5m)
- **No Active Bouncers** — enforcement silently broken (5m)
- **Bouncer Not Pulling** — per-bouncer staleness (15m)
- **Alert Surge** — active attack in progress (>20 alerts in 5m)
- **Machine Agent Stale** — agent stopped pushing events (5m)

Each rule includes `description` annotations with `cscli` investigation commands.

## Compatibility

Built and tested against **CrowdSec v1.7.x**. Metric names changed significantly in v1.7 (added `_total` suffix, `cs_buckets_*` → `cs_bucket_*`, removed `cs_machine_last_push` and `cs_lapi_decisions_received`). These dashboards and alerts use the current v1.7 metric names.

## Blog Post

`blog/crowdsec-grafana-observability.md` covers the full setup including the log acquisition gotchas (source: docker vs source: file), pipeline verification steps, and what the metrics actually mean from an SRE and security perspective.
