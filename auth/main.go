package main

import (
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
)

func main() {
	// 读取环境变量
	username := os.Getenv("OKTA_USERNAME")
	password := os.Getenv("OKTA_PASSWORD")
	if username == "" || password == "" {
		log.Fatalf("Environment variables OKTA_USERNAME or OKTA_PASSWORD are not set.")
	}

	// 构造 HTTP 客户端和 Cookie Jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatalf("Failed to create cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}

	// 登录并获取 stateToken 和 MFA URL
	stateToken, mfaURL := login(client, username, password)

	// 调用 MFA 验证逻辑
	if mfaURL != "" {
		log.Println("Starting MFA process...")
		performMFA(client, stateToken, mfaURL)
	} else {
		log.Println("MFA URL is empty. Skipping MFA.")
	}
}
