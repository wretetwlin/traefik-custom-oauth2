package traefik_custom_oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config Plugin configuration.
type Config struct {
	AuthGrantRequest AuthGrantRequestConfig `json:"authGrantRequest,omitempty"`
	Trace            bool                   `json:"trace,omitempty"` // additional logging
}

type AuthGrantRequestConfig struct {
	URL                   string   `json:"url,omitempty"` // the URL to request the token
	GrantType             string   `json:"grantType,omitempty"`
	User                  string   `json:"user,omitempty"`
	Pass                  string   `json:"pass,omitempty"`
	environment           string   `json:"environment,omitempty"`
	agencyName            string   `json:"agencyName,omitempty"`
	ClientId              string   `json:clientId,omitempty`
	ClientSecret          string   `json:clientSecret,omitempty`
	Scope                 string   `json:"scope,omitempty"`
	Headers               []Header `json:"headers,omitempty"`
	ExpiresMarginSeconds  int      `json:"expiresMarginSeconds,omitempty"`  // the margin in seconds to subtract from the expires_in value
	BasicAuthSkipEncoding bool     `json:"basicAuthSkipEncoding,omitempty"` // skip url-encoding of user and pass for basic auth
}

type Header struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

type state struct {
	token   string
	expires time.Time
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// CustomOauth2 plugin.
type CustomOauth2 struct {
	next                          http.Handler
	name                          string
	trace                         bool
	user                          string
	pass                          string
	environment                   string
	agencyName                    string
	clientId                      string
	clientSecret                  string
	authGrantUrl                  string
	authGrantType                 string
	authGrantScope                string
	authGrantHeaders              map[string]string
	authGrantExpiresMarginSeconds int64
	state                         state
}

// New plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	authGrantHeaders := make(map[string]string)
	for _, header := range config.AuthGrantRequest.Headers {
		hdrName, err := fromFlexibleField("header.name", header.Name)
		if err != nil {
			return nil, err
		}
		hdrValue, err := fromFlexibleField("header.value", header.Value)
		if err != nil {
			return nil, err
		}
		authGrantHeaders[hdrName] = hdrValue
	}

	grantType, err := fromFlexibleField("grantType", config.AuthGrantRequest.GrantType)
	if err != nil {
		return nil, err
	}
	if grantType == "" {
		return nil, fmt.Errorf("custom-oauth2 missing value for grant_type")
	}

	environment, err := fromFlexibleField("environment", config.AuthGrantRequest.environment)
	if err != nil {
		return nil, err
	}

	agencyName, err := fromFlexibleField("agencyName", config.AuthGrantRequest.agencyName)
	if err != nil {
		return nil, err
	}

	user, err := fromFlexibleField("user", config.AuthGrantRequest.User)
	if err != nil {
		return nil, err
	}
	pass, err := fromFlexibleField("pass", config.AuthGrantRequest.User)
	if err != nil {
		return nil, err
	}

	clientId, err := fromFlexibleField("clientId", config.AuthGrantRequest.ClientId)
	if err != nil {
		return nil, err
	}

	clientSecret, err := fromFlexibleField("clientSecret", config.AuthGrantRequest.ClientSecret)
	if err != nil {
		return nil, err
	}

	if grantType == "client_credentials" {
		if user != "" {
			basicAuthSkipEncoding := config.AuthGrantRequest.BasicAuthSkipEncoding
			basicAuth := queryEncode(user, basicAuthSkipEncoding) + ":" + queryEncode(pass, basicAuthSkipEncoding)
			authGrantHeaders["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(basicAuth))
		}

		if clientId != "" {
			//using client_id and client_secret as basic authentication
			basicAuthSkipEncoding := config.AuthGrantRequest.BasicAuthSkipEncoding
			basicAuth := queryEncode(clientId, basicAuthSkipEncoding) + ":" + queryEncode(clientSecret, basicAuthSkipEncoding)
			authGrantHeaders["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(basicAuth))
		}
	}

	grantUrl, err := fromFlexibleField("url", config.AuthGrantRequest.URL)
	if err != nil {
		return nil, err
	}
	if grantUrl == "" {
		return nil, fmt.Errorf("custom-oauth2 missing value for url")
	}

	return &CustomOauth2{
		next:                          next,
		name:                          name,
		trace:                         config.Trace,
		user:                          user,
		pass:                          pass,
		environment:                   environment,
		agencyName:                    agencyName,
		clientId:                      clientId,
		clientSecret:                  clientSecret,
		authGrantUrl:                  grantUrl,
		authGrantType:                 grantType,
		authGrantScope:                config.AuthGrantRequest.Scope,
		authGrantHeaders:              authGrantHeaders,
		authGrantExpiresMarginSeconds: maxInt(1, int64(config.AuthGrantRequest.ExpiresMarginSeconds)),
		state: state{
			token:   "",
			expires: time.Time{},
		},
	}, nil
}

func (c *CustomOauth2) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if time.Now().After(c.state.expires) {
		data := url.Values{
			"grant_type": {c.authGrantType},
		}
		if c.authGrantScope != "" {
			data.Set("scope", c.authGrantScope)
		}
		if c.authGrantType == "password" {
			data.Set("client_id", c.clientId)
			data.Set("client_secret", c.clientSecret)
			data.Set("username", c.user)
			data.Set("password", c.pass)
			data.Set("environment", c.environment)
			data.Set("agency_name", c.agencyName)
		}

		agReq, err := http.NewRequest("POST", c.authGrantUrl, strings.NewReader(data.Encode()))
		if err != nil {
			serveInternalError(rw, fmt.Sprintf("new-request: %v", err))
			return
		}
		agReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		agReq.Header.Set("Accept", "*/*")
		for name, value := range c.authGrantHeaders {
			agReq.Header.Set(name, value)
		}

		agRes, err := http.DefaultClient.Do(agReq)
		if err != nil {
			serveInternalError(rw, fmt.Sprintf("do-request: %v", err))
			return
		}
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(agRes.Body)

		body, _ := io.ReadAll(agRes.Body)
		if c.trace {
			_, _ = os.Stdout.WriteString(fmt.Sprintf("custom-oauth2 auth-grant response: %s\n", body))
		}

		if agRes.StatusCode != 200 {
			serveError(rw, fmt.Sprintf("status-code: %d", agRes.StatusCode), agRes.StatusCode)
			return
		}

		var responseData map[string]interface{}
		err = json.Unmarshal(body, &responseData)
		if err != nil {
			serveInternalError(rw, fmt.Sprintf("unmarshall: %v", err))
			return
		}
		accessToken, ok := responseData["access_token"].(string)
		if !ok {
			serveInternalError(rw, fmt.Sprintf("access_token not found"))
			return
		}
		expiresInStr, okStr := responseData["expires_in"].(string)
		expiresInFlt, okFlt := responseData["expires_in"].(float64)
		if !okFlt && okStr {
			expiresInFlt, err = strconv.ParseFloat(expiresInStr, 64)
		}
		if !okFlt && err != nil {
			serveInternalError(rw, fmt.Sprintf("expires_in not found or not parseable"))
			return
		}
		expiresIn := int64(expiresInFlt)
		expiresInAdjusted := maxInt(1, expiresIn-c.authGrantExpiresMarginSeconds)
		c.state.token = accessToken
		c.state.expires = time.Now().Truncate(time.Second).Add(time.Duration(expiresInAdjusted) * time.Second)
		if c.trace {
			_, _ = os.Stdout.WriteString(fmt.Sprintf("custom-oauth2: token=%s  expires=%d  adjusted=%d\n",
				c.state.token, expiresIn, expiresInAdjusted))
		}
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.state.token))
	c.next.ServeHTTP(rw, req)
}

func serveError(rw http.ResponseWriter, msg string, status int) {
	_, _ = os.Stderr.WriteString(fmt.Sprintf("custom-oauth2: error: %s\n", msg))
	rw.WriteHeader(status)
	_, err := rw.Write([]byte(fmt.Sprintf("%s: %s", http.StatusText(status), msg)))
	if err != nil {
		fmt.Printf("%s", msg)
	}
}

func serveInternalError(rw http.ResponseWriter, msg string) {
	serveError(rw, msg, http.StatusInternalServerError)
}

func queryEncode(s string, skip bool) string {
	if skip {
		return s
	}
	return url.QueryEscape(s)
}

// keep minimum Go version below 1.21
func maxInt(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func fromFlexibleField(fieldName string, fieldValue string) (string, error) {
	r, err := fromFlexibleValue(fieldValue)
	if err != nil {
		return "", fmt.Errorf("custom-oauth2 failed to parse field '%s=%s': %v", fieldName, fieldValue, err)
	}
	return r, nil
}

// fromFlexibleValue parses a flexible value string and returns the corresponding value.
// The flexible value string can be in the following formats:
// - Direct value: "value"
// - File value: "~file~<file_path>"
// - Environment variable value: "~env~<env_var>"
// - Base64 encoded environment variable value: "~base64~env~<env_var>"
//
// Parameters:
// - fieldValue: the flexible value string to parse.
//
// Returns:
// - The parsed value as a string.
// - An error if the format is invalid or if there is an issue reading the value.
func fromFlexibleValue(fieldValue string) (string, error) {
	if !strings.HasPrefix(fieldValue, "~") {
		return fieldValue, nil
	}

	var isBase64 int
	if strings.HasPrefix(fieldValue, "~base64~") {
		isBase64 = 1
	} else {
		isBase64 = 0
	}
	parts := strings.SplitN(fieldValue, "~", 1+1+1+isBase64)
	if len(parts) < 1+1+1+isBase64 {
		return "", fmt.Errorf("invalid flexible fieldValue format: '%s'", fieldValue)
	}
	encoding := parts[isBase64]
	source := parts[isBase64+1]
	value := parts[1+1+isBase64]

	switch source {
	case "file":
		valueBytes, err := os.ReadFile(value)
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(string(valueBytes))
	case "env":
		envValue, envExists := os.LookupEnv(value)
		if !envExists {
			return "", fmt.Errorf("environment variable '%s' not found", value)
		}
		value = envValue
	case "direct":
		// value is already set correctly
	default:
		return "", fmt.Errorf("unknown source: %s", source)
	}

	if isBase64 == 1 {
		if encoding == "base64" {
			// try to support both common Base64 variants
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				decoded, err = base64.URLEncoding.DecodeString(value)
			}
			if err != nil {
				decoded, err = base64.RawURLEncoding.DecodeString(value)
			}
			if err != nil {
				return "", err
			}
			value = string(decoded)
		} else {
			return "", fmt.Errorf("unknown encoding: %s", encoding)
		}
	}
	return value, nil
}
