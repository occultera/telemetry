-- npx wrangler d1 execute occultera-telemetry --remote --file=schema.sql
CREATE TABLE IF NOT EXISTS errors (
  fingerprint TEXT PRIMARY KEY,
  exception   TEXT NOT NULL,
  category    TEXT,
  frames      TEXT NOT NULL,          -- JSON array of "module:function"
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  count       INTEGER NOT NULL DEFAULT 1,
  versions    TEXT NOT NULL DEFAULT '[]',
  installs    TEXT NOT NULL DEFAULT '[]',   -- install ids (random, not reversible), capped at 50
  issue       INTEGER
);
CREATE TABLE IF NOT EXISTS usage (
  install     TEXT NOT NULL,
  week        TEXT NOT NULL,          -- ISO year-week, e.g. 2026-W48
  received    TEXT NOT NULL,
  payload     TEXT NOT NULL,          -- the validated event, JSON
  PRIMARY KEY (install, week)
);
