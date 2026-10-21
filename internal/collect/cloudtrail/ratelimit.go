package cloudtrail

import (
	"context"
	"sync"
	"time"
)

// IntervalLimiter はリクエストの間隔を Interval 以上に保つレート制限 (トークンバケットのバースト 1 と同じ挙動)。
// 決定: golang.org/x/time/rate は使わない。使うのは「毎秒 n 回・バースト 1 の Wait」だけで、標準ライブラリで十数行に収まるため (設計書 1 章、ADR 0018)。
// 時刻と待ちは Now / Sleep で差し替えられる。複数の goroutine から呼んでよい。
type IntervalLimiter struct {
	Interval time.Duration
	Now      func() time.Time
	Sleep    func(ctx context.Context, d time.Duration) error

	mu   sync.Mutex
	next time.Time // 次に許される時刻。ゼロ値なら即時
}

// NewIntervalLimiter は毎秒 perSecond 回までのレート制限を返す。
func NewIntervalLimiter(perSecond int) *IntervalLimiter {
	return &IntervalLimiter{Interval: time.Second / time.Duration(perSecond), Now: time.Now, Sleep: sleepFor}
}

// Wait は次の枠まで待つ。ctx が取り消されたら予約した枠を返してエラーにする。
func (l *IntervalLimiter) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	now := l.Now()
	slot := now
	if l.next.After(now) {
		slot = l.next
	}
	prev := l.next
	l.next = slot.Add(l.Interval)
	l.mu.Unlock()
	d := slot.Sub(now)
	if d <= 0 {
		return nil
	}
	if err := l.Sleep(ctx, d); err != nil {
		l.mu.Lock()
		// 後から別の予約が入っていなければ枠を返す
		if l.next.Equal(slot.Add(l.Interval)) {
			l.next = prev
		}
		l.mu.Unlock()
		return err
	}
	return nil
}
