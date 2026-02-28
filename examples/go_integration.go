package main

import (
	"context"
	"fmt"
	"log"

	"github.com/sashabaranov/go-openai"
)

func main() {
	// ============================================================
	//  TRƯỚC KHI CÓ PRIVACYGUARD:
	// ============================================================
	//  client := openai.NewClient("sk-...")

	// ============================================================
	//  SAU KHI CÀI PRIVACYGUARD:
	//  Chỉ thay đổi config, toàn bộ code gọi AI giữ nguyên.
	// ============================================================
	config := openai.DefaultConfig("sk-...")
	config.BaseURL = "http://localhost:8080/v1" // ← trỏ vào PrivacyGuard

	client := openai.NewClientWithConfig(config)

	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT4o,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: "CCCD của tôi là 012345678901, SĐT 0901234567",
				},
			},
		},
	)

	if err != nil {
		log.Fatalf("API error: %v", err)
	}

	// PII đã được bảo vệ xuyên suốt, bạn nhận lại dữ liệu thật
	fmt.Println(resp.Choices[0].Message.Content)
}
