package cloudtrail

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/CircleAround/arata/internal/collect"
)

// fakeClock は Sleep で時刻を進めるだけの時計。
type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	slept []time.Duration
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.slept = append(f.slept, d)
	f.now = f.now.Add(d)
	return nil
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func newTestLimiter(clk *fakeClock) *IntervalLimiter {
	l := NewIntervalLimiter(requestsPerSecond)
	l.Now = clk.Now
	l.Sleep = clk.Sleep
	return l
}

func TestIntervalLimiterSpacesRequests(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)}
	l := newTestLimiter(clk)
	start := clk.Now()
	for i := 0; i < 5; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// 2 req/s・バースト 1: 1 回目は待たず、以降は 500ms ずつ
	if got := clk.Now().Sub(start); got != 2*time.Second {
		t.Fatalf("5 requests must take 2s, took %v (slept %v)", got, clk.slept)
	}
	for _, d := range clk.slept {
		if d != 500*time.Millisecond {
			t.Fatalf("each wait must be 500ms: %v", clk.slept)
		}
	}
}

func TestIntervalLimiterNoBurstAfterIdle(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)}
	l := newTestLimiter(clk)
	_ = l.Wait(context.Background())
	clk.advance(10 * time.Second) // 長く空いても溜めるのは 1 回分だけ
	_ = l.Wait(context.Background())
	if len(clk.slept) != 0 {
		t.Fatalf("first after idle must not wait: %v", clk.slept)
	}
	_ = l.Wait(context.Background())
	if len(clk.slept) != 1 || clk.slept[0] != 500*time.Millisecond {
		t.Fatalf("second after idle must wait 500ms: %v", clk.slept)
	}
	clk.advance(200 * time.Millisecond) // 前回から 200ms なら残り 300ms
	_ = l.Wait(context.Background())
	if clk.slept[1] != 300*time.Millisecond {
		t.Fatalf("partial wait: %v", clk.slept)
	}
}

func TestIntervalLimiterCanceled(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)}
	l := newTestLimiter(clk)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ctx: %v", err)
	}
	// 取り消された Wait は枠を使わない
	if err := l.Wait(context.Background()); err != nil || len(clk.slept) != 0 {
		t.Fatalf("slot must not be consumed by a canceled wait: %v %v", err, clk.slept)
	}
}

func TestIntervalLimiterCanceledWhileWaiting(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)}
	l := newTestLimiter(clk)
	_ = l.Wait(context.Background())
	l.Sleep = func(context.Context, time.Duration) error { return context.DeadlineExceeded }
	if err := l.Wait(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("sleep error must be returned: %v", err)
	}
	l.Sleep = clk.Sleep
	// 待ちが取り消されたら予約を返す: 次は 1 回目から 500ms 後の枠
	_ = l.Wait(context.Background())
	if len(clk.slept) != 1 || clk.slept[0] != 500*time.Millisecond {
		t.Fatalf("reservation must be released: %v", clk.slept)
	}
}

func TestIntervalLimiterConcurrent(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)}
	l := newTestLimiter(clk)
	var mu sync.Mutex
	var slots []time.Duration
	l.Sleep = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		slots = append(slots, d)
		mu.Unlock()
		return nil // 時計は進めない: 各 Wait が予約した枠の待ち時間だけを見る
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = l.Wait(context.Background()) }()
	}
	wg.Wait()
	// 同時に来ても枠は重ならない: 0 (待ちなし), 500ms, 1s, 1.5s
	seen := map[time.Duration]bool{}
	for _, d := range slots {
		seen[d] = true
	}
	if len(slots) != 3 || !seen[500*time.Millisecond] || !seen[time.Second] || !seen[1500*time.Millisecond] {
		t.Fatalf("concurrent slots: %v", slots)
	}
}

// 適応リトライ (スロットル時の指数バックオフ) は既定のレート制限と組み合わせても変わらない。
func TestThrottleRetryWithDefaultLimiter(t *testing.T) {
	base := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	clk := &fakeClock{now: base}
	fake := &Fake{Pages: [][]types.Event{{ev("e-root", base.Add(time.Hour), rootLogin)}}, FailFirst: 3, FailErr: apiErr{"ThrottlingException"}}
	c := New("trail", RegionClient{Region: "ap-northeast-1", API: fake})
	c.Limiter = newTestLimiter(clk)
	var backoffs []time.Duration
	c.Sleep = func(ctx context.Context, d time.Duration) error {
		backoffs = append(backoffs, d)
		return clk.Sleep(ctx, d)
	}
	if err := c.Collect(context.Background(), collect.Window{From: base, To: base.Add(24 * time.Hour)}, &captured{}); err != nil {
		t.Fatal(err)
	}
	if len(backoffs) != 3 || backoffs[0] != time.Second || backoffs[1] != 2*time.Second || backoffs[2] != 4*time.Second {
		t.Fatalf("backoff must double from 1s: %v", backoffs)
	}
	// バックオフの後はレート制限の枠が空いているので追加の待ちは無い (待ちはバックオフ分だけ)
	if got := clk.Now().Sub(base); got != 7*time.Second {
		t.Fatalf("elapsed %v (slept %v)", got, clk.slept)
	}
}
