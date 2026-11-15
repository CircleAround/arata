package config

import (
	"fmt"
	"time"
)

// CollectHourlyMode は cloudwatch-logs を時の単位で続きだけ読む読み方 (sources[].collect。ADR 0065)。
const CollectHourlyMode = "hourly"

// CollectHourly は時の単位で続きだけを読むソースか。
func (s Source) CollectHourly() bool { return s.Collect == CollectHourlyMode }

// validateCollect は sources[].collect を確かめる。
//
// 決定 (ADR 0065): 最初の版はソースごとの opt-in。実データで値が同じことを確かめた後の版で既定にし、この項目を要らなくする
// (行き着く先は、種類を問わず 1 つの収集の間隔で全部を集め、利用者が決めるのは間隔だけ)。
// request_lines は request_id で行をまとめるので、時の境目をまたぐリクエストが割れる。text は日次の集計を持たない (log_hygiene だけ)。どちらも対象外
func (s *Source) validateCollect() error {
	switch s.Collect {
	case "":
		return nil
	case CollectHourlyMode:
	default:
		return fmt.Errorf("collect %q: want %q (or omit it to read each day from its start)", s.Collect, CollectHourlyMode)
	}
	if s.Kind != KindCloudWatchLogs {
		return fmt.Errorf("collect is only for kind %s", KindCloudWatchLogs)
	}
	if s.Format == FormatRequestLines || s.Format == FormatText {
		return fmt.Errorf("collect: %s is not for format %s (request_lines groups lines by request id across hours; text has no daily aggregates)", CollectHourlyMode, s.Format)
	}
	return nil
}

// validateHourlyEndpoints は、時の単位で読むソースを見る endpoint_abuse の時間幅が 1 時間を割り切るかを確かめる (幅が時の境目をまたがないため)。
func (c *Config) validateHourlyEndpoints() error {
	w := c.Checks.EndpointAbuse.WindowDuration()
	if w <= 0 || time.Hour%w == 0 {
		return nil
	}
	hourly := map[string]bool{}
	for _, s := range c.Sources {
		if s.CollectHourly() {
			hourly[s.ID] = true
		}
	}
	for _, ep := range c.Checks.EndpointAbuse.Endpoints {
		for _, id := range ep.Sources {
			if hourly[id] {
				return fmt.Errorf("window %s must divide an hour for source %s (collect: %s), e.g. 5m, 10m, 15m, 20m, 30m or 1h", c.Checks.EndpointAbuse.Window, id, CollectHourlyMode)
			}
		}
	}
	return nil
}
