package notify

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/report/schema"
)

// 入力ディレクトリのファイル名 (arata run --out / arata report --out が書くもの)。
const (
	ReportJSON   = "report.json"
	ReportMD     = "report.md"
	NotifiedFile = ".aratam-notified"
)

// 報告の種類。
const (
	KindRun    = "run"    // arata run (hourly / daily / weekly などのプロファイル)
	KindPeriod = "period" // arata report --from --to (期間レポート)
)

// Input は入力ディレクトリから読んだ報告。
type Input struct {
	Dir         string
	Kind        string
	Run         *schema.Report       // Kind == KindRun
	Period      *schema.PeriodReport // Kind == KindPeriod
	JSON        []byte               // report.json の原文 (LLM に渡すのはこれだけ)
	Markdown    string               // report.md。無ければ report.json から作る
	GeneratedAt time.Time
}

// InputError は「arata が実行されていない / 失敗した」とみなす入力の問題 (終了コード 4)。
type InputError struct {
	Code   string // INPUT_MISSING / INPUT_INVALID / INPUT_STALE
	Reason string
}

func (e *InputError) Error() string { return e.Code + ": " + e.Reason }

// 入力の問題の code (ログの固定語彙)。
const (
	CodeInputMissing = "INPUT_MISSING"
	CodeInputInvalid = "INPUT_INVALID"
	CodeInputStale   = "INPUT_STALE"
)

// ReadInput は dir の report.json を読み、古さを検査する。
//
// 決定:
//   - report.json が JSON として読めない・generated_at が無いか RFC 3339 でない場合も「失敗した」とみなす (INPUT_INVALID)。
//   - 未知のフィールドは無視する (arata が足したフィールドで aratam が止まらないように)。
//   - report.md が無ければ report.json から arata と同じ関数で作る (同じリポジトリの schema パッケージ)。
func ReadInput(dir string, now time.Time, maxAge time.Duration) (*Input, error) {
	path := filepath.Join(dir, ReportJSON)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, &InputError{Code: CodeInputMissing, Reason: fmt.Sprintf("%s がありません", path)}
	}
	if err != nil {
		return nil, &InputError{Code: CodeInputMissing, Reason: fmt.Sprintf("%s を読めません (%v)", path, errors.Unwrap(err))}
	}
	in := &Input{Dir: dir, JSON: b}
	var head struct {
		Kind        string `json:"kind"`
		GeneratedAt string `json:"generated_at"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, &InputError{Code: CodeInputInvalid, Reason: fmt.Sprintf("%s を解釈できません (%v)", path, err)}
	}
	switch head.Kind {
	case "period":
		in.Kind = KindPeriod
		in.Period = &schema.PeriodReport{}
		err = json.Unmarshal(b, in.Period)
	case "":
		in.Kind = KindRun
		in.Run = &schema.Report{}
		err = json.Unmarshal(b, in.Run)
	default:
		return nil, &InputError{Code: CodeInputInvalid, Reason: fmt.Sprintf("%s の kind %q は知らない種類です", path, head.Kind)}
	}
	if err != nil {
		return nil, &InputError{Code: CodeInputInvalid, Reason: fmt.Sprintf("%s を解釈できません (%v)", path, err)}
	}
	in.GeneratedAt, err = time.Parse(time.RFC3339, head.GeneratedAt)
	if err != nil {
		return nil, &InputError{Code: CodeInputInvalid, Reason: fmt.Sprintf("%s の generated_at %q を解釈できません", path, head.GeneratedAt)}
	}
	if age := now.Sub(in.GeneratedAt); age > maxAge {
		return nil, &InputError{Code: CodeInputStale, Reason: fmt.Sprintf("%s の generated_at %s は max_age %s より古い", path, head.GeneratedAt, maxAge)}
	}
	if md, err := os.ReadFile(filepath.Join(dir, ReportMD)); err == nil {
		in.Markdown = string(md)
	} else if in.Run != nil {
		in.Markdown = in.Run.Markdown()
	} else {
		in.Markdown = in.Period.Markdown()
	}
	return in, nil
}

// Name は report.json の name。
func (in *Input) Name() string {
	if in.Run != nil {
		return in.Run.Name
	}
	return in.Period.Name
}

// Key は二重送信の防止に使う、この報告の識別子。
// 決定: run は run_id。期間レポートは run_id を持たないので、期間と生成時刻から作る (同じ期間を作り直したら別の報告として送る)。
func (in *Input) Key() string {
	if in.Run != nil {
		if in.Run.RunID != "" {
			return in.Run.RunID
		}
		return "run@" + in.Run.GeneratedAt
	}
	return fmt.Sprintf("period:%s/%s@%s", in.Period.Period.From, in.Period.Period.To, in.Period.GeneratedAt)
}

// Notified は .aratam-notified に同じ報告の識別子があるか。
func Notified(dir, key string) bool {
	b, err := os.ReadFile(filepath.Join(dir, NotifiedFile))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == key
}

// MarkNotified は .aratam-notified に識別子を書く (一時ファイルからの rename で置き換える)。
// 決定: 中身は直近の 1 件だけ。入力ディレクトリは監査対象・プロファイルごとに分かれ、arata は毎回上書きするため、直近と比べれば足りる。
func MarkNotified(dir, key string) error {
	tmp, err := os.CreateTemp(dir, NotifiedFile+".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.WriteString(key + "\n"); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, NotifiedFile))
}
