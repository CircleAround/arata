package config

import (
	"fmt"

	"github.com/CircleAround/arata/internal/pathids"
)

// PathIDs はソースの path_ids (パスの中の ID の位置。ADR 0071 の 2 節・0087 の 5・6 節)。
// 書かなければ、パスの型の要るチェック (user_id_enumeration・user_path_breadth) は skip する。
//
// 決定: max_segments は書くことを求める (暗黙の既定を持たない。ADR 0014)。formats は書かなければ拡張子を外さない。
// 今の NormalizePath (WAF・探索パスの key) は変えない (0087 の 6 節)。この規則を読むのは、パスの型の要るチェックだけ。
type PathIDs struct {
	// Segments は、区間 1 つの全体に当たれば ID とみなす正規表現 (RE2。^ $ は arata が付ける)。
	Segments []string `yaml:"segments"`
	// Templates は区間の形では分からない ID (:id) と、ID ではないが形を問わない区間 (:any) の位置。
	Templates []string `yaml:"templates"`
	// Formats は最後の区間の末尾から外す形式の拡張子 (英小文字と数字)。
	Formats []string `yaml:"formats"`
	// MaxSegments はこれより深いパスの後ろを `/…` にまとめる区間の数 (1〜12)。
	MaxSegments int `yaml:"max_segments"`

	compiled *pathids.Compiled
}

// PathRules は検証した path_ids の規則 (書かなければ nil)。
func (s Source) PathRules() *pathids.Compiled {
	if s.PathIDs == nil {
		return nil
	}
	return s.PathIDs.compiled
}

// CompilePathIDs は path_ids を検証し、規則を組み立てる (Load が呼ぶ。設定を手で組むテストも使う)。
func (s *Source) CompilePathIDs() error {
	if s.PathIDs == nil {
		return nil
	}
	if s.Yields != YieldsHTTPAccess && s.Yields != YieldsHTTPUser {
		return fmt.Errorf("path_ids is only for sources that yield %s or %s (format %s does not)", YieldsHTTPAccess, YieldsHTTPUser, s.Format)
	}
	p := s.PathIDs
	c, err := pathids.Compile(pathids.Rules{Segments: p.Segments, Templates: p.Templates, Formats: p.Formats, MaxSegments: p.MaxSegments})
	if err != nil {
		return fmt.Errorf("path_ids: %w", err)
	}
	p.compiled = c
	return nil
}
