package utils

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/exp/rand"
)

func GetParam(args []string, moduleSymbol string) (string, error) {
	for i, arg := range args {
		if arg == moduleSymbol {
			if len(args) != i+1 {
				return args[i+1], nil
			}
			err := errors.New("doesn't have param value")
			return "", err
		}
	}
	return "", nil
}

func CheckPortOpen(host string, port string) {
	timeout := time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		fmt.Println("Connecting error:", err)
	}
	if conn != nil {
		defer conn.Close()
		fmt.Println("Opened", net.JoinHostPort(host, port))
	}
}

func ValidIP4(ipAddress string) bool {
	ipAddress = strings.Trim(ipAddress, " ")

	re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)

	return re.MatchString(ipAddress)
}

type Color string

const (
	ColorBlack  Color  = "\u001b[30m"
	ColorRed    Color  = "\u001b[31m"
	ColorGreen  Color  = "\u001b[32m"
	ColorYellow Color  = "\u001b[33m"
	ColorBlue   Color  = "\u001b[34m"
	ColorReset  Color  = "\u001b[0m"
	ClearLine   string = "\033[2K\n"
)

func Colorize(color Color, message string) {
	fmt.Println(string(color), message, string(ColorReset))
}

func ColorizeFMT(color Color, message string) string {
	return fmt.Sprintf("%s%s%s\n", string(color), message, string(ColorReset))
}

func HttpRequest(targetUrl string, method string, data []byte, client http.Client) (*http.Response, error) {
	request, err := http.NewRequest(method, targetUrl, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	response, err := client.Do(request)
	if err != nil {
		return response, err
	}

	return response, nil
}

func ProgressBar(allItems int, currentItem int, progress *int) {
	percent := (currentItem * 100) / allItems

	// bar := percent - *progress
	// *progress = percent

	fmt.Printf("\r[%s] %d", strings.Repeat("-", percent), percent)
}

func RandStringRunes(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func IsIPv6(ipAddress string) bool {
	ipAddress = strings.TrimSpace(ipAddress)

	ip := net.ParseIP(ipAddress)
	return ip != nil && ip.To4() == nil
}

func UnmarshallJsonString(jsonString string) (map[string]interface{}, error) {
	if jsonString == "" {
		return nil, fmt.Errorf("json string is empty")
	}

	jsonString = strings.TrimSpace(jsonString)
	if jsonString == "" {
		return nil, fmt.Errorf("json string is empty after trim")
	}

	var result map[string]interface{}

	if err := json.Unmarshal([]byte(jsonString), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	if result == nil {
		return nil, fmt.Errorf("JSON root is not an object (got null or array/primitive)")
	}

	return result, nil
}

func ExportersExtractCmdline(data map[string]interface{}) (string, bool) {
	if data == nil {
		return "", false
	}

	cmdlineIface, ok := data["cmdline"]
	if !ok || cmdlineIface == nil {
		return "", false
	}

	switch v := cmdlineIface.(type) {
	case string:
		if strings.TrimSpace(v) != "" {
			return v, true
		}
	case []interface{}:
		var sb strings.Builder
		for _, arg := range v {
			if arg != nil {
				sb.WriteString(fmt.Sprintf("%v ", arg))
			}
		}
		result := strings.TrimSpace(sb.String())
		if result != "" {
			return result, true
		}
	default:
		// fallback для чисел, bool и прочего
		s := fmt.Sprintf("%v", v)
		if strings.TrimSpace(s) != "" {
			return s, true
		}
	}

	return "", false
}
