package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

func performMFA(client *http.Client, stateToken, mfaURL string) {
	// 构造 MFA 请求体
	mfaPayload := map[string]string{"stateToken": stateToken}
	payloadBytes, err := json.Marshal(mfaPayload)
	if err != nil {
		log.Fatalf("Failed to marshal MFA payload: %v", err)
	}

	// 发送 MFA 请求
	req, err := http.NewRequest("POST", mfaURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Fatalf("Failed to create MFA request: %v", err)
	}
	loginOktaMfaAddHeaders(req, stateToken)

	// 输出请求信息
	log.Printf("Sending MFA request to URL: %s with stateToken: %s", mfaURL, stateToken)

	// 检查 MFA 状态
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to perform MFA request: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("MFA response status: %s", resp.Status)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("MFA failed with status code: %d", resp.StatusCode)
	}
}

func loginOktaMfaAddHeaders(req *http.Request, stateToken string) {
	req.Header.Set("accept", "application/json")
	req.Header.Set("accept-language", "zh-CN")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("cookie", "DT=DI1LAoR05_WR32BfmZh_LPWnw; JSESSIONID=04067E70BE57F0F2AD9B32F172ABC26A; oktaStateToken=" + stateToken)
	req.Header.Set("origin", "https://suse.okta.com")
	req.Header.Set("priority", "u=1, i")
	req.Header.Set("referer", "https://suse.okta.com/signin/verify/okta/push")
	req.Header.Set("sec-ch-ua", `"Google Chrome",v="131", "Chromium",v="131", "Not_A Brand",v="24"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", "macOS")
	req.Header.Set("sec-ch-ua-platform-version", "15.1.1")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("x-okta-user-agent-extended", "okta-auth-js/7.8.1 okta-signin-widget-7.25.1")
}