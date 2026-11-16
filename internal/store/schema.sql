-- arata SQLite スキーマ (設計書 5-2)。runs / principals / principal_ips / events / metrics / findings。
-- 時刻は RFC3339 (UTC) の文字列で保存する。
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS runs (
  id          TEXT PRIMARY KEY,
  profile     TEXT NOT NULL,
  window_from TEXT NOT NULL,
  window_to   TEXT NOT NULL,
  started_at  TEXT NOT NULL,
  finished_at TEXT,
  status      TEXT NOT NULL,
  stats       TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS runs_profile_started ON runs(profile, started_at);

CREATE TABLE IF NOT EXISTS principals (
  arn        TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  status     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS principal_ips (
  arn        TEXT NOT NULL,
  ip         TEXT NOT NULL,
  country    TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  count      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (arn, ip)
);

CREATE TABLE IF NOT EXISTS events (
  event_id       TEXT PRIMARY KEY,
  time           TEXT NOT NULL,
  source         TEXT NOT NULL,
  name           TEXT NOT NULL,
  event_source   TEXT NOT NULL DEFAULT '',
  principal_arn  TEXT NOT NULL DEFAULT '',
  principal_kind TEXT NOT NULL DEFAULT '',
  ip             TEXT NOT NULL DEFAULT '',
  region         TEXT NOT NULL DEFAULT '',
  resource       TEXT NOT NULL DEFAULT '',
  read_only      INTEGER NOT NULL DEFAULT 0,
  error_code     TEXT NOT NULL DEFAULT '',
  data           TEXT NOT NULL DEFAULT '{}',
  -- 最初に収集した run の時刻 (固定幅の RFC3339)。再走査で遅れて届いたイベントの判定に使う (ADR 0013)。'' は schema 3 より前の収集
  collected_at   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_time ON events(time);
CREATE INDEX IF NOT EXISTS events_name ON events(name);

CREATE TABLE IF NOT EXISTS findings (
  id           TEXT PRIMARY KEY,
  "check"      TEXT NOT NULL,
  key          TEXT NOT NULL,
  severity     TEXT NOT NULL,
  summary      TEXT NOT NULL DEFAULT '',
  first_seen   TEXT NOT NULL,
  last_seen    TEXT NOT NULL,
  last_changed TEXT NOT NULL,
  status       TEXT NOT NULL,
  reported_at  TEXT,
  snooze_until TEXT,
  fingerprint  TEXT NOT NULL DEFAULT '',
  data         TEXT NOT NULL DEFAULT '{}',
  -- ack / snooze したときの重大度。観測がこれより重くなったら再報告する (ADR 0022)。open / resolved では空
  suppressed_severity TEXT NOT NULL DEFAULT '',
  UNIQUE ("check", key)
);
CREATE INDEX IF NOT EXISTS findings_status ON findings(status);

-- 日次集計 (Logs Insights の集計クエリの結果)。同じ (date, source, metric, key) は置き換える。
CREATE TABLE IF NOT EXISTS metrics (
  date   TEXT NOT NULL,
  source TEXT NOT NULL,
  "from" TEXT NOT NULL DEFAULT '',
  metric TEXT NOT NULL,
  key    TEXT NOT NULL DEFAULT '',
  value  REAL NOT NULL DEFAULT 0,
  PRIMARY KEY (date, source, metric, key)
);
CREATE INDEX IF NOT EXISTS metrics_metric_date ON metrics(metric, date);

-- 時ごとの集計 (schema 6。ADR 0064)。同じ (hour, source, metric, key) は置き換える。Metrics は日の値を時の和として返し、
-- 時ごとの行がある (date, source, metric) では metrics の日の行を使わない。date は hour の日 (YYYY-MM-DD。索引のため持つ)。
CREATE TABLE IF NOT EXISTS metrics_hourly (
  hour   TEXT NOT NULL,
  date   TEXT NOT NULL,
  source TEXT NOT NULL,
  "from" TEXT NOT NULL DEFAULT '',
  metric TEXT NOT NULL,
  key    TEXT NOT NULL DEFAULT '',
  value  REAL NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, source, metric, key)
);
CREATE INDEX IF NOT EXISTS metrics_hourly_day ON metrics_hourly(metric, date, source);

-- 部分の行 (schema 7。ADR 0065)。Logs Insights のクエリが時の単位で返した行を、(source, query, hour) ごとに丸ごと置き換えて残す。
-- 日の値 (metrics) はその日の全部の時の行から Go で作る。raw には書かない (作業用。rebuild は既存の SQLite から引き継ぐ)。
-- rows は行の JSON の配列。date は hour の日 (古い日を消すため)。
CREATE TABLE IF NOT EXISTS metric_parts (
  source TEXT NOT NULL,
  query  TEXT NOT NULL,
  hour   TEXT NOT NULL,
  date   TEXT NOT NULL,
  rows   TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY (source, query, hour)
);
CREATE INDEX IF NOT EXISTS metric_parts_date ON metric_parts(source, date);

-- スナップショット (認証情報レポート・GuardDuty・Access Analyzer・姿勢)。収集が成功したときだけ (kind, source) 単位で丸ごと置き換える (ADR 0015)。
CREATE TABLE IF NOT EXISTS snapshot_items (
  kind         TEXT NOT NULL,
  source       TEXT NOT NULL,
  key          TEXT NOT NULL,
  data         TEXT NOT NULL DEFAULT '{}',
  collected_at TEXT NOT NULL,
  PRIMARY KEY (kind, source, key)
);

-- finding の状態遷移の履歴 (new / changed / recurred / resolved)。期間レポート (report --from --to) の元 (ADR 0016)。
-- schema 4 より前の run の遷移は残っていない (meta.history_since 以降だけ)。
CREATE TABLE IF NOT EXISTS finding_events (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id TEXT NOT NULL,
  "check"    TEXT NOT NULL,
  key        TEXT NOT NULL,
  class      TEXT NOT NULL,
  severity   TEXT NOT NULL,
  summary    TEXT NOT NULL DEFAULT '',
  at         TEXT NOT NULL,
  run_id     TEXT NOT NULL DEFAULT '',
  profile    TEXT NOT NULL DEFAULT '',
  data       TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS finding_events_at ON finding_events(at);

-- 人の片付けの操作 (ack / snooze / resolve / approve) の記録 (schema 8。ADR 0068)。1 回の操作を 1 行で追記し、書き換えない。
-- 最後の操作は finding ごとの最大の seq。severity と status_before は操作したときの値。schema 8 より前の操作は残っていない。
CREATE TABLE IF NOT EXISTS finding_actions (
  seq           INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id    TEXT NOT NULL,
  "check"       TEXT NOT NULL,
  key           TEXT NOT NULL,
  action        TEXT NOT NULL,
  "by"          TEXT NOT NULL DEFAULT '',
  reason        TEXT NOT NULL DEFAULT '',
  forced        INTEGER NOT NULL DEFAULT 0,
  severity      TEXT NOT NULL,
  status_before TEXT NOT NULL,
  snooze_until  TEXT,
  at            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS finding_actions_finding ON finding_actions(finding_id, seq);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
