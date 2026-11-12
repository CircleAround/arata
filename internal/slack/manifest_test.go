package slack

import (
	"bytes"
	"os"
	"reflect"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

// 配布する Slack アプリの manifest (deploy/slack/app-manifest.yaml) は、投稿だけのアプリのまま保つ (aratam 設計書 4-1 章)。
//   - bot の scope は chat:write だけ (chat:write.public・channels:read などを足さない)。利用者の scope は持たない
//   - 受け口 (Event Subscriptions・Interactivity・slash commands・Socket Mode・OAuth のリダイレクト) を持たない
//   - トークンのローテーションは無効 (aratam は更新の仕組みを持たない。有効にするとトークンが 12 時間で切れる)
func TestAppManifestIsPostOnly(t *testing.T) {
	b, err := os.ReadFile("../../deploy/slack/app-manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		DisplayInformation struct {
			Name        string `yaml:"name"`
			Description string `yaml:"description"`
		} `yaml:"display_information"`
		Features    map[string]yaml.Node `yaml:"features"`
		OAuthConfig map[string]yaml.Node `yaml:"oauth_config"`
		Settings    map[string]any       `yaml:"settings"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true) // 上の 4 つ以外の節 (functions・workflows など) が足されたら落ちる
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	if m.DisplayInformation.Name != "arata" || m.DisplayInformation.Description == "" || len([]rune(m.DisplayInformation.Description)) > 140 {
		t.Errorf("display_information: %+v", m.DisplayInformation)
	}

	if got := keys(m.Features); !reflect.DeepEqual(got, []string{"bot_user"}) {
		t.Errorf("features must have bot_user only (no slash_commands, shortcuts, app_home ...): %v", got)
	}
	var bot struct {
		DisplayName  string `yaml:"display_name"`
		AlwaysOnline bool   `yaml:"always_online"`
	}
	if n := m.Features["bot_user"]; n.Decode(&bot) != nil || bot.DisplayName != "arata" || bot.AlwaysOnline {
		t.Errorf("bot_user: %+v", bot)
	}

	if got := keys(m.OAuthConfig); !reflect.DeepEqual(got, []string{"scopes"}) {
		t.Errorf("oauth_config must have scopes only (no redirect_urls): %v", got)
	}
	var scopes map[string][]string
	if n := m.OAuthConfig["scopes"]; n.Decode(&scopes) != nil || !reflect.DeepEqual(scopes, map[string][]string{"bot": {"chat:write"}}) {
		t.Errorf("scopes must be bot: [chat:write] only: %v", scopes)
	}

	want := map[string]any{"org_deploy_enabled": false, "socket_mode_enabled": false, "is_hosted": false, "token_rotation_enabled": false}
	if !reflect.DeepEqual(m.Settings, want) {
		t.Errorf("settings (no event_subscriptions, no interactivity): got %v, want %v", m.Settings, want)
	}
}

func keys(m map[string]yaml.Node) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
