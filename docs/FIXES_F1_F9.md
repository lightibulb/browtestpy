# LeakGuard fixes F1–F9

Applied by `fix_leakguard.sh`. Backups live in `.leakguard_fix_backup/<timestamp>/`.

| Finding | Change |
|---|---|
| F1 | Triage table only — no code change. |
| F2 | Fingerprint + WebRTC + public-IP are now measured **in the visitor's browser** and sent with the scan. Server Playwright is a labelled fallback (`layer2.source == "server"`), and its `webdriver` flag / container timezone are no longer scored as user leaks. |
| F3 | `analyze()` tracks measurement **coverage**. Unmeasured checks emit findings; unknown IP ⇒ `FAIL`, incomplete coverage ⇒ `INCONCLUSIVE`. `PASS` now means "measured and clean". |
| F4 | `httpx[socks]` (socksio). SOCKS errors are explained. `socks5h` normalised and proxy credentials split for Chromium. |
| F5 | `check_dns()` / `check_stun()` are proxy-aware: they report `skipped` instead of measuring the host and fabricating a critical leak. |
| F6 | Redis `volatile-lru` (queue keys have no TTL and can no longer be evicted), worker `plan: standard`, broker `visibility_timeout`, 3 s Redis timeouts, and a bounded redelivery guard so an OOM-killed task cannot loop forever. |
| F7 | UI: `AbortController` timeouts, `res.ok` checks, real error details, exponential backoff, 429 + `Retry-After` handling, 300 s budget matching Celery, re-poll on tab focus. Server: separate 300 req/min bucket for polling GETs. |
| F8 | Placeholder is a public example; helper text explains server reachability and `ALLOW_PRIVATE_PROXIES`; 422 details are rendered. |
| F9 | Full `scan_id` + Copy, a ready-made `--attach` command, "Fill agent field". History is scoped to an opaque `lg_sid` cookie; in production, scan/agent reads are ownership-checked. The worker no longer writes a global history list. |

## Manual steps the script cannot do for you

1. **Render dashboard**: the blueprint changes only take effect on a Blueprint
   sync/redeploy. Confirm the worker is on a ≥2 GB plan and is actually running.
2. Verify: `curl -s https://<app>/health` → `celery_workers: true`.
3. Verify: `curl -s https://<app>/ready` → `{"status":"ok","redis":true}`.
4. Redis policy change may require a restart of the Redis instance.

## Rollback

```bash
bash fix_leakguard.sh --restore .leakguard_fix_backup/<timestamp>
```
