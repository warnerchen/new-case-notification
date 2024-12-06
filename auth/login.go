package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

func login(client *http.Client, username, password string) (string, string) {
	// 构造登录数据
	loginData := map[string]interface{}{
		"password": password,
		"username": username,
		"options": map[string]bool{
			"warnBeforePasswordExpired": true,
			"multiOptionalFactorEnroll": true,
		},
	}
	payload, err := json.Marshal(loginData)
	if err != nil {
		log.Fatalf("Failed to marshal login data: %v", err)
	}

	// 构造 POST 请求
	loginURL := "https://suse.okta.com/api/v1/authn"
	req, err := http.NewRequest("POST", loginURL, bytes.NewBuffer(payload))
	if err != nil {
		log.Fatalf("Failed to create login request: %v", err)
	}
	loginOktaAddHeaders(req)

	// 发送请求
	log.Println("Sending login request to Okta API...")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to perform login: %v", err)
	}
	defer resp.Body.Close()

	// 输出响应信息
	log.Printf("Received login response with status: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Login failed with status code: %d", resp.StatusCode)
	}

	// 解析响应
	var respBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		log.Fatalf("Failed to decode response body: %v", err)
	}

	// 提取 stateToken
	stateToken, ok := respBody["stateToken"].(string)
	if !ok {
		log.Fatalf("Failed to extract stateToken from response.")
	}

	// 提取 MFA URL
	mfaURL := extractMFAURL(respBody, username)
	return stateToken, mfaURL
}

func extractMFAURL(respBody map[string]interface{}, username string) string {
	embedded, ok := respBody["_embedded"].(map[string]interface{})
	if !ok {
		log.Fatalf("Failed to extract _embedded field.")
	}
	factors, ok := embedded["factors"].([]interface{})
	if !ok {
		log.Fatalf("Failed to extract factors array.")
	}

	log.Printf("Checking factors for user: %s", username)
	for _, factor := range factors {
		factorMap, ok := factor.(map[string]interface{})
		if !ok {
			continue
		}
		profile, ok := factorMap["profile"].(map[string]interface{})
		if !ok {
			continue
		}
		if profile["credentialId"] == username && profile["deviceType"] == "SmartPhone_IPhone" {
			links, ok := factorMap["_links"].(map[string]interface{})
			if ok {
				verify, ok := links["verify"].(map[string]interface{})
				if ok {
					log.Printf("MFA URL found: %s", verify["href"].(string))
					return verify["href"].(string)
				}
			}
		}
	}
	log.Println("No MFA URL found for the user.")
	return ""
}

func loginOktaAddHeaders(req *http.Request) {
	req.Header.Set("accept", "application/json")
	req.Header.Set("accept-language", "zh-CN")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("cookie", "DT=DI1LAoR05_WR32BfmZh_LPWnw; JSESSIONID=04067E70BE57F0F2AD9B32F172ABC26A")
	req.Header.Set("origin", "https://suse.okta.com")
	req.Header.Set("priority", "u=1, i")
	req.Header.Set("referer", "https://suse.okta.com/login/login.htm?fromURI=%2Fhome%2Fsalesforce%2F0oa1adbgwc8ZLbQ7U357%2F46")
	req.Header.Set("sec-ch-ua", `"Google Chrome",v="131", "Chromium",v="131", "Not_A Brand",v="24"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", "macOS")
	req.Header.Set("sec-ch-ua-platform-version", "15.1.1")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("x-device-fingerprint", "MTdxkWJC6RBANLoylRlvfYXxMEDu6J4M|9300edd7bc053d238142c4b3e70a9e3f46eb1942e66926f0266f739e9afc3cef|b9de177e084bcb100cd66303be586b01")
	req.Header.Set("x-okta-user-agent-extended", "okta-auth-js/7.8.1 okta-signin-widget-7.25.1")
}