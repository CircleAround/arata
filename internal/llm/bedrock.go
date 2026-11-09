package llm

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

// ConverseAPI は bedrockruntime の Converse だけを使う (テストは httptest に向けたクライアントを渡す)。
type ConverseAPI interface {
	Converse(ctx context.Context, in *bedrockruntime.ConverseInput, opts ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error)
}

// Bedrock は Bedrock の Converse API を呼ぶプロバイダ (provider: bedrock)。必要な権限は bedrock:InvokeModel だけ。
type Bedrock struct {
	Client ConverseAPI
	// Model は推論プロファイル ID (llm.model)。
	Model string
}

// maxTokens は応答の上限。決まった JSON (3 章) には十分な長さ。
const maxTokens = 4096

// NewBedrock は AWS SDK の標準の認証チェーン (profile 指定可) でクライアントを作る。
// 決定: SDK の自動再試行は切る (RetryMaxAttempts 1)。再試行は notify で 1 回までと決めているため、二重に重ねない。
func NewBedrock(ctx context.Context, region, profile, model string) (*Bedrock, error) {
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region), awsconfig.WithRetryMaxAttempts(1)}
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("bedrock: load AWS config: %w", err)
	}
	return &Bedrock{Client: bedrockruntime.NewFromConfig(cfg), Model: model}, nil
}

// Summarize は Converse を 1 回呼ぶ。system は system に、report.json は user のメッセージに入れる。温度は 0。
func (b *Bedrock) Summarize(ctx context.Context, system string, reportJSON []byte) ([]byte, error) {
	out, err := b.Client.Converse(ctx, &bedrockruntime.ConverseInput{
		ModelId: aws.String(b.Model),
		System:  []types.SystemContentBlock{&types.SystemContentBlockMemberText{Value: system}},
		Messages: []types.Message{{
			Role:    types.ConversationRoleUser,
			Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: string(reportJSON)}},
		}},
		InferenceConfig: &types.InferenceConfiguration{MaxTokens: aws.Int32(maxTokens)}, // temperature は送らない (docs/aratam.md 3-1)
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("bedrock: %w", ctx.Err())
		}
		return nil, fmt.Errorf("bedrock: %w", err)
	}
	msg, ok := out.Output.(*types.ConverseOutputMemberMessage)
	if !ok {
		return nil, errors.New("bedrock: no message in the response")
	}
	var sb strings.Builder
	for _, c := range msg.Value.Content {
		if t, ok := c.(*types.ContentBlockMemberText); ok {
			sb.WriteString(t.Value)
		}
	}
	if out.StopReason == types.StopReasonMaxTokens {
		return nil, fmt.Errorf("bedrock: the response was cut at %d tokens", maxTokens)
	}
	if strings.TrimSpace(sb.String()) == "" {
		return nil, errors.New("bedrock: empty response")
	}
	return []byte(sb.String()), nil
}
