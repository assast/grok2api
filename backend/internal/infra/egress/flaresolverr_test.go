package egress

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFlareSolverrSolveUsesNodeProxyAndFiltersCookies(t *testing.T) {
	var requestPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1" || request.Method != http.MethodPost {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&requestPayload); err != nil {
			t.Fatal(err)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"status":"ok","solution":{"userAgent":"Mozilla/5.0 Chrome/146.0.0.0 Safari/537.36","cookies":[{"name":"cf_clearance","value":"clear"},{"name":"sso","value":"secret"},{"name":"__cf_bm","value":"bm"}]}}`))
	}))
	defer server.Close()

	solution, err := (flaresolverrSolver{}).Solve(context.Background(), ClearanceConfig{
		FlareSolverrURL: server.URL, TargetURL: "https://grok.com", Timeout: time.Second,
	}, "socks5h://proxy:1080")
	if err != nil {
		t.Fatal(err)
	}
	if solution.Cookies != "cf_clearance=clear; __cf_bm=bm" || solution.UserAgent == "" {
		t.Fatalf("solution = %#v", solution)
	}
	if requestPayload["cmd"] != "request.get" || requestPayload["url"] != "https://grok.com" {
		t.Fatalf("payload = %#v", requestPayload)
	}
	proxy, ok := requestPayload["proxy"].(map[string]any)
	if !ok || proxy["url"] != "socks5h://proxy:1080" || proxy["username"] != nil || proxy["password"] != nil {
		t.Fatalf("proxy payload = %#v", requestPayload["proxy"])
	}
}

func TestFlareSolverrSolveSplitsProxyCredentials(t *testing.T) {
	var requestPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if err := json.NewDecoder(request.Body).Decode(&requestPayload); err != nil {
			t.Fatal(err)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"status":"ok","solution":{"userAgent":"Mozilla/5.0 Chrome/146.0.0.0 Safari/537.36","cookies":[{"name":"cf_clearance","value":"clear"}]}}`))
	}))
	defer server.Close()

	if _, err := (flaresolverrSolver{}).Solve(context.Background(), ClearanceConfig{
		FlareSolverrURL: server.URL, TargetURL: "https://grok.com", Timeout: time.Second,
	}, "http://leno:vUd5gqxqbYKYZcfPzanIN30RKRq8pM0lrWiN9FBuEotLD7X5C8VvzeUvV7x4XeMi@100.94.3.10:30080"); err != nil {
		t.Fatal(err)
	}
	proxy, ok := requestPayload["proxy"].(map[string]any)
	if !ok || proxy["url"] != "http://100.94.3.10:30080" || proxy["username"] != "leno" ||
		proxy["password"] != "vUd5gqxqbYKYZcfPzanIN30RKRq8pM0lrWiN9FBuEotLD7X5C8VvzeUvV7x4XeMi" {
		t.Fatalf("proxy payload = %#v", requestPayload["proxy"])
	}
}

func TestFlareSolverrProxyPayload(t *testing.T) {
	for _, test := range []struct {
		name     string
		input    string
		url      string
		username string
		password string
		hasAuth  bool
	}{
		{name: "no credentials", input: "socks5h://proxy:1080", url: "socks5h://proxy:1080"},
		{name: "user and password", input: "http://leno:secret@100.94.3.10:30080", url: "http://100.94.3.10:30080", username: "leno", password: "secret", hasAuth: true},
		{name: "username only", input: "http://leno.acc123@10.144.144.10:2260", url: "http://10.144.144.10:2260", username: "leno.acc123", password: "", hasAuth: true},
		{name: "percent-encoded userinfo", input: "http://leno.%7Baccount%7D:p%40ss@10.144.144.10:2260", url: "http://10.144.144.10:2260", username: "leno.{account}", password: "p@ss", hasAuth: true},
		{name: "empty input", input: "", url: ""},
	} {
		payload := flaresolverrProxyPayload(test.input)
		if payload["url"] != test.url {
			t.Fatalf("%s url = %q, want %q", test.name, payload["url"], test.url)
		}
		if test.hasAuth {
			if payload["username"] != test.username || payload["password"] != test.password {
				t.Fatalf("%s credentials = %#v", test.name, payload)
			}
			continue
		}
		if _, ok := payload["username"]; ok {
			t.Fatalf("%s unexpectedly included credentials: %#v", test.name, payload)
		}
		if _, ok := payload["password"]; ok {
			t.Fatalf("%s unexpectedly included credentials: %#v", test.name, payload)
		}
	}
}

func TestFlareSolverrEndpointAcceptsBaseAndV1Path(t *testing.T) {
	for input, expected := range map[string]string{
		"http://flaresolverr:8191":   "http://flaresolverr:8191/v1",
		"http://flaresolverr:8191/":  "http://flaresolverr:8191/v1",
		"https://solver.example/api": "https://solver.example/api/v1",
	} {
		actual, err := flaresolverrEndpoint(input)
		if err != nil || actual != expected {
			t.Fatalf("endpoint(%q) = %q, %v", input, actual, err)
		}
	}
}

func TestSanitizeFlareSolverrMessageRedactsCredentials(t *testing.T) {
	message := sanitizeFlareSolverrMessage("proxy socks5h://user:secret@resin:2260 failed; token=abc123 Authorization: Bearer.SECRET cookie=sso-value")
	for _, secret := range []string{"user", "secret", "abc123", "Bearer.SECRET", "sso-value"} {
		if strings.Contains(message, secret) {
			t.Fatalf("sanitized message leaked %q: %q", secret, message)
		}
	}
	if !strings.Contains(message, "socks5h://***:***@") {
		t.Fatalf("proxy scheme was not retained safely: %q", message)
	}
}
