package http

import (
	"fmt"
	"net/http"
)

var DefaultPorts = []string{
	"80", "443", "8080", "8000", "8443", "8081", "81", "8888", "888",
	"8001", "82", "88", "9000", "5000", "4443", "8083", "8085", "554",
	"84", "8082", "83", "8010", "8181", "10000", "9090", "9001", "8880",
	"8008", "9999",
}

func ProbeHTTP(ip string, timeout int) string {
	client := getClient(timeout)

	for _, port := range DefaultPorts {
		switch port {
		case "80":
			// For port 80, try HTTP first
			httpURL := fmt.Sprintf("http://%s:%s", ip, port)
			if isAlive(client, httpURL) {
				return httpURL
			}
		default:
			// For all other ports, try HTTPS first
			httpsURL := fmt.Sprintf("https://%s:%s", ip, port)
			if isAlive(client, httpsURL) {
				return httpsURL
			}

			httpURL := fmt.Sprintf("http://%s:%s", ip, port)
			if isAlive(client, httpURL) {
				return httpURL
			}
		}
	}

	return ""
}

func isAlive(client *http.Client, url string) bool {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err == nil && resp != nil {
		resp.Body.Close()
		return true
	}

	return false
}
