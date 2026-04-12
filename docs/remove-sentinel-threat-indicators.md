# Remove-SentinelThreatIndicators

Detailed behavior and workflow notes for:
- `Scripts/Remove-SentinelThreatIndicators.ps1`

## How It Works at Scale

The script uses a count-and-drain workflow designed for large datasets.

Safety guard:
- `SourceFilter` is mandatory.
- If `SourceFilter` is missing, empty, or contains only blank values, the script aborts before any delete operations.

1. **Strict preflight count:** It gets an exact source-filter count first. If exact source count is unavailable, delete mode stops.
2. **Fetch path:** It uses the filtered query endpoint (`2025-09-01`) to fetch one page at a time.
3. **Delete in small working sets:** It processes one fetched page at a time, deletes that page, then fetches again. This keeps memory bounded to roughly one page.
4. **Rate and retry controls:** Delete throughput is paced by `$TargetDeleteRatePerSecond` and worker count (`$ConcurrentWorkers`). `401` triggers token refresh/retry, and `429` uses Retry-After backoff.
   Rate conversion reference: `req/hour = req/s * 3600` (examples: `1.0 -> 3600/hour`, `10.0 -> 36000/hour`).
5. **Progress and recount:** During the run, it periodically refreshes remaining count (default 60s) for reconciled progress and ETA.
6. **End-of-run reconciliation:** If processed totals do not match initial count, it performs a reconciliation pass and logs mismatch details.

Operator note: `ConcurrentWorkers=1` runs sequentially, and values greater than `1` run parallel deletes. In both modes, sustained throughput is globally rate-limited by `TargetDeleteRatePerSecond`.

Operational details:
- The script uses the **Microsoft Sentinel / SecurityInsights REST API** directly via `Invoke-RestMethod`.
- Token refresh is handled automatically on `401 Unauthorized` responses.
- Rate limiting (`429 Too Many Requests`) is handled with automatic backoff and retry on delete, query, and count requests.
- The script requires **PowerShell 7+**.

For most production cleanup runs, start with `ConcurrentWorkers=1..2` and `TargetDeleteRatePerSecond=1.0`, then increase only if throttling remains low.

> **Note:** Depending on the total number of indicators to delete, the job can take **several hours** to complete. For workspaces with millions of indicators, plan accordingly and ensure the host running the script remains active for the duration.
