# Logging Reference

This page describes the logging model used in the Microsoft Defender Threat Intelligence Toolkit.

It provides a shared format overview first, then script-specific logging details.

As additional scripts are added to this repository, extend this page with script-specific sections.

## Format

The toolkit uses logfmt (`key=value`) lines.
- Reference: https://brandur.org/logfmt
- Timestamp field (`ts`) is ISO 8601 UTC with `Z` suffix.

Each line always starts with:
- `ts`
- `level`
- `run_id`

Then event-specific fields follow.

## Remove-SentinelThreatIndicators.ps1

This section documents logging details for:
- `Scripts/Remove-SentinelThreatIndicators.ps1`

### Default Log Location

- `<script folder>\Logs\Remove-SentinelThreatIndicators_<yyyyMMdd_HHmmss>.log`

A new file is created per run. The `Logs` folder is auto-created if missing.

### Example

```log
ts=2026-04-12T13:44:10Z level=info run_id=11571876 event=run_started subscription_id=00000000-0000-0000-0000-000000000000 resource_group=rg_sentinel01 workspace=AVSentinel01 source_filter=FEODOtrackerIPBlockList
ts=2026-04-12T13:44:11Z level=info run_id=11571876 event=preflight_config run_id=11571876 log_file=/logs/Remove-SentinelThreatIndicators_20260412_154410.log
ts=2026-04-12T13:44:11Z level=info run_id=11571876 event=delete_started source_filter=FEODOtrackerIPBlockList found=9340
ts=2026-04-12T13:47:23Z level=info run_id=11571876 event=delete_progress deleted=1172 failed=0 found=9340 remaining=8165 eta="22m 3s"
```
