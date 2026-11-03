package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CircleAround/arata/internal/engine"
	"github.com/CircleAround/arata/internal/store"
	"github.com/CircleAround/arata/internal/subcmd"
)

// rebuildOutput は rebuild の結果 (--format json)。
type rebuildOutput struct {
	Database        string         `json:"database"`
	FromScratch     bool           `json:"from_scratch"`
	PrincipalStatus string         `json:"principal_status"` // 引き継ぎなら carried_over、--from-scratch なら unknown / baseline
	CarriedOver     []string       `json:"carried_over"`
	Files           int            `json:"files"`
	Records         map[string]int `json:"records"`
	Malformed       int            `json:"malformed"`
	UnknownKinds    map[string]int `json:"unknown_kinds"`
	Warnings        []string       `json:"warnings"`
	Backup          string         `json:"backup,omitempty"`
}

var carriedOver = []string{"runs", "findings", "finding_events", "meta", "principal status"}

func newRebuildCmd(d *Deps, g *globalFlags) *subcmd.Command {
	var o store.RebuildOptions
	var format string
	cmd := &subcmd.Command{
		Use:   "rebuild",
		Short: "raw JSONL の原本から audit.sqlite を作り直す (findings・runs・主体の状態は既存の SQLite から引き継ぐ)",
		Long: `raw/<source>/<日付>.jsonl の原本から audit.sqlite を作り直す (ADR 0033)。
events・principals・principal_ips・metrics・snapshot_items は記録したときと同じ規則で入れ直す。
raw に無いもの (runs・findings・finding_events・meta・主体の状態 approved / baseline など) は、既定では既存の SQLite から引き継ぐ。
既存の SQLite が無い・壊れているときは --from-scratch で raw だけから作る (findings は空になり、次の run で未解決のものが new として再報告される。
主体は unknown、--baseline なら baseline)。一時ファイルに作ってから入れ替え、元のファイルは audit.sqlite.bak に 1 世代残す。`,
		Run: func(ctx context.Context, _ []string) error {
			if format != "text" && format != "json" {
				return formatErr(format, "text|json")
			}
			if o.Baseline && !o.FromScratch {
				return &engine.ExitError{Code: engine.CodeConfigInvalid, Exit: engine.ExitConfig, Err: fmt.Errorf("--baseline needs --from-scratch (otherwise the principals' status is carried over)")}
			}
			cfg, err := loadConfig(d, g)
			if err != nil {
				return err
			}
			res, err := engine.Rebuild(ctx, cfg, d.Engine, o)
			if err != nil {
				return err
			}
			for _, w := range res.Warnings {
				d.Engine.Logger.Warn("rebuild: " + w)
			}
			if o.FromScratch {
				d.Engine.Logger.Warn("rebuilt from raw only: findings, runs and their history start empty; every open finding is reported again as new on the next run",
					"principal_status", principalStatus(o))
			}
			out := rebuildOutput{Database: filepath.Join(res.Dir, "audit.sqlite"), FromScratch: res.FromScratch, PrincipalStatus: principalStatus(o), CarriedOver: []string{},
				Files: res.Files, Records: map[string]int{}, Malformed: res.Malformed, UnknownKinds: res.UnknownKinds, Warnings: res.Warnings, Backup: res.Backup}
			if !o.FromScratch {
				out.CarriedOver = carriedOver
			}
			for k, n := range res.Records {
				out.Records[string(k)] = n
			}
			if out.Warnings == nil {
				out.Warnings = []string{}
			}
			if format == "json" {
				b, err := json.MarshalIndent(out, "", "  ")
				if err != nil {
					return err
				}
				_, err = d.Stdout.Write(append(b, '\n'))
				return err
			}
			writeRebuildText(d, out)
			return nil
		},
	}
	cmd.BoolVar(&o.FromScratch, "from-scratch", false, "既存の SQLite を読まずに raw だけから作る (findings・runs は空から。壊れた SQLite の復旧用)")
	cmd.BoolVar(&o.Baseline, "baseline", false, "--from-scratch で、全主体を baseline (new_principal の対象外。init と同じ扱い) にする。既定は unknown")
	cmd.StringVar(&format, "format", "text", "出力形式 (text|json)")
	return cmd
}

func principalStatus(o store.RebuildOptions) string {
	switch {
	case !o.FromScratch:
		return "carried_over"
	case o.Baseline:
		return store.PrincipalBaseline
	}
	return store.PrincipalUnknown
}

func writeRebuildText(d *Deps, out rebuildOutput) {
	w := d.Stdout
	fmt.Fprintf(w, "rebuilt %s from %d raw files\n", out.Database, out.Files)
	if out.FromScratch {
		fmt.Fprintf(w, "from scratch: runs, findings and their history are empty; principals: %s\n", out.PrincipalStatus)
	} else {
		fmt.Fprintf(w, "carried over from the existing database: %s\n", strings.Join(out.CarriedOver, ", "))
	}
	fmt.Fprintln(w, "records:")
	kinds := make([]string, 0, len(out.Records))
	for k := range out.Records {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		fmt.Fprintf(w, "  %-24s %d\n", k, out.Records[k])
	}
	if out.Malformed > 0 || len(out.UnknownKinds) > 0 {
		fmt.Fprintf(w, "skipped: %d malformed lines, unknown kinds %v\n", out.Malformed, out.UnknownKinds)
	}
	if len(out.Warnings) > 0 {
		fmt.Fprintln(w, "warnings:")
		for _, s := range out.Warnings {
			fmt.Fprintf(w, "  - %s\n", s)
		}
	}
	if out.Backup != "" {
		fmt.Fprintf(w, "backup: %s\n", out.Backup)
	}
}
