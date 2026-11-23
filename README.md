# occultera-telemetry

The collector behind Occultera's error reports and anonymous usage data — a Cloudflare Worker with a D1 database.
What the application sends and why: wiki page *Telemetry* and `app/telemetry/` in the main repository.

- Accepts only the two structured event types (`error`, `usage`, schema 1); anything else is refused with 400.
- Stores no IP address and no request header. Rows are deleted after 90 days (daily cron).
- Crashes are grouped by fingerprint in D1; repeats only update the counters. No issue is opened automatically: the
  maintainer reviews the table and opens issues by hand (set the `GITHUB_TOKEN` secret to switch automatic issues on).

## Deploy (once)

```sh
cd /mnt/c/ESD/Wazuh-Auto-Kontrol/occultera-telemetry
npx wrangler d1 create occultera-telemetry          # copy the database_id into wrangler.jsonc
npx wrangler d1 execute occultera-telemetry --remote --file=schema.sql
npx wrangler secret put GITHUB_TOKEN                 # fine-grained token: occultera/occultera only, Issues read/write
npx wrangler deploy
curl -s -X POST https://telemetry.occultera.dev/v1/events -H 'content-type: application/json' -d '{"kind":"x"}'   # → 400 unknown kind
```

The repository labels `crash`, `telemetry` and `wazuh-5` must exist:

```sh
gh label create crash --repo occultera/occultera --color B60205 --description "Crash or error report"
gh label create telemetry --repo occultera/occultera --color 5319E7 --description "Opened by the telemetry collector"
gh label create wazuh-5 --repo occultera/occultera --color 0E8A16 --description "Wazuh 5.x compatibility"
```

## Look at the data

```sh
npx wrangler d1 execute occultera-telemetry --remote --command "SELECT exception, count, versions, issue FROM errors ORDER BY last_seen DESC LIMIT 20"
npx wrangler d1 execute occultera-telemetry --remote --command "SELECT json_extract(payload,'$.app') v, count(*) FROM usage WHERE week = strftime('%Y-W%W','now') GROUP BY v"
npx wrangler d1 execute occultera-telemetry --remote --command "SELECT value, count(*) FROM usage, json_each(json_extract(payload,'$.wazuh')) GROUP BY value"
```

License: AGPL-3.0-only.
