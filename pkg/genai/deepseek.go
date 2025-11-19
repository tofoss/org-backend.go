package genai

import (
	"context"
	"fmt"
	"log"

	deepseek "github.com/cohesion-org/deepseek-go"
)

type DeepseekClient struct {
	client *deepseek.Client
}

func NewDeepseekClient() DeepseekClient {
	client := deepseek.NewClient("")

	return DeepseekClient{
		client,
	}
}

func (d *DeepseekClient) Chat(
	systemContent, userContent string,
	JSONMode bool,
	ctx context.Context,
) (string, error) {
	request := &deepseek.ChatCompletionRequest{
		Model:    deepseek.DeepSeekChat,
		JSONMode: JSONMode,
		Messages: []deepseek.ChatCompletionMessage{
			{Role: deepseek.ChatMessageRoleSystem, Content: systemContent},
			{Role: deepseek.ChatMessageRoleUser, Content: userContent},
		},
	}

	response, err := d.client.CreateChatCompletion(ctx, request)
	if err != nil {
		return "", fmt.Errorf("could not complete chat %v", err)
	}

	log.Printf(
		"Chat %s request was successful. Used %d tokens.\n",
		response.ID,
		response.Usage.TotalTokens,
	)

	if len(response.Choices) == 0 {
		return "", fmt.Errorf("no choices returned from API")
	}

	return response.Choices[0].Message.Content, nil
}
