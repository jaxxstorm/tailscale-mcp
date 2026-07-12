// main.go

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/alecthomas/kong"
	"github.com/jaxxstorm/tailscale-mcp/internal/curatedtools"
	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/tailscale/hujson"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"
	tsapi "tailscale.com/client/tailscale/v2"
	_ "tailscale.com/feature/identityfederation"
	_ "tailscale.com/feature/oauthkey"
	"tailscale.com/hostinfo"
	ipnstore "tailscale.com/ipn/store"
	_ "tailscale.com/ipn/store/awsstore"
	_ "tailscale.com/ipn/store/kubestore"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

type CLI struct {
	Tailnet       string `env:"TAILSCALE_TAILNET" required:""`
	Credential    string `env:"TAILSCALE_OAUTH_TOKEN" required:"" help:"OAuth, federated, or bearer credential for Tailscale startup and API access"`
	OAuthClientID string `name:"oauth-client-id" env:"TAILSCALE_OAUTH_CLIENT_ID" help:"OAuth client ID to use when TAILSCALE_OAUTH_TOKEN is a raw tskey-client secret"`
	Hostname      string `env:"TS_HOSTNAME" default:"ts-mcp"`
	Port          int    `env:"TS_PORT" default:"8080"`
	AdvertiseTags string `env:"TS_ADVERTISE_TAGS" help:"Comma-separated Tailscale tags to advertise when minting tsnet auth keys from OAuth or federated credentials"`
	State         string `env:"TSNET_STATE" help:"tsnet state location: empty or file:// uses ./tsnet-<hostname>/tailscaled.state; file://<dir> uses <dir>/tailscaled.state; kube://<secret> uses a Kubernetes Secret; aws://<region>/<account>/parameter/<name> or aws://arn:aws:ssm:... uses AWS SSM"`
	ForceLogin    bool   `env:"TSNET_FORCE_LOGIN" help:"Force tsnet to use the supplied startup credential even when local state exists"`
	LocalCLI      bool   `env:"TAILSCALE_LOCAL_CLI" help:"Enable optional read-only tools that shell out to the local tailscale CLI"`
	Debug         bool   `short:"d"`
	Version       bool   `short:"v"`
	Stdio         bool   `help:"Use deprecated stdio mode instead of Streamable HTTP" default:"false"`
}

const (
	mcpServerName               = "ts-mcp"
	streamableHTTPTransportName = "Streamable HTTP"
	mcpEndpointPath             = "/mcp"
	defaultLocalStreamableAddr  = "127.0.0.1:8080"
	tailscaleOAuthTokenEnv      = "TAILSCALE_OAUTH_TOKEN"
)

var buildVersion = "dev"
var logger *zap.Logger
var registerTSNetBuildInfoOnce sync.Once

type CredentialKind string

const (
	CredentialUnknown   CredentialKind = "unknown"
	CredentialBearer    CredentialKind = "bearer"
	CredentialOAuth     CredentialKind = "oauth"
	CredentialFederated CredentialKind = "federated"
)

type TailscaleCredential struct {
	Kind         CredentialKind
	Token        string
	ClientID     string
	ClientSecret string
	IDToken      string
	Audience     string
	Scopes       []string
}

type credentialJSON struct {
	Type         string   `json:"type"`
	Token        string   `json:"token"`
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	IDToken      string   `json:"idToken"`
	Audience     string   `json:"audience"`
	Scopes       []string `json:"scopes"`
}

func ParseTailscaleCredential(raw string) (TailscaleCredential, error) {
	return ParseTailscaleCredentialWithClientID(raw, "")
}

func ParseTailscaleCredentialWithClientID(raw, clientID string) (TailscaleCredential, error) {
	raw = strings.TrimSpace(raw)
	clientID = strings.TrimSpace(clientID)
	if raw == "" {
		return TailscaleCredential{}, fmt.Errorf("%s is required", tailscaleOAuthTokenEnv)
	}

	if strings.HasPrefix(raw, "{") {
		var cfg credentialJSON
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return TailscaleCredential{}, fmt.Errorf("failed to parse %s JSON: %w", tailscaleOAuthTokenEnv, err)
		}
		cred := TailscaleCredential{
			Kind:         CredentialKind(strings.ToLower(cfg.Type)),
			Token:        strings.TrimSpace(cfg.Token),
			ClientID:     strings.TrimSpace(cfg.ClientID),
			ClientSecret: strings.TrimSpace(cfg.ClientSecret),
			IDToken:      strings.TrimSpace(cfg.IDToken),
			Audience:     strings.TrimSpace(cfg.Audience),
			Scopes:       cfg.Scopes,
		}
		if cred.Kind == "" {
			cred.Kind = classifyCredential(cred)
		}
		return cred, cred.validate()
	}

	if strings.HasPrefix(raw, "tskey-client-") {
		if clientID != "" {
			cred := TailscaleCredential{Kind: CredentialOAuth, ClientID: clientID, ClientSecret: raw}
			return cred, cred.validate()
		}
		return TailscaleCredential{}, fmt.Errorf("%s contains an OAuth client secret without a client ID; use JSON like {\"type\":\"oauth\",\"clientId\":\"k...\",\"clientSecret\":\"tskey-client-...\",\"scopes\":[\"all\"]}", tailscaleOAuthTokenEnv)
	}

	cred := TailscaleCredential{Kind: CredentialBearer, Token: raw}
	return cred, nil
}

func classifyCredential(cred TailscaleCredential) CredentialKind {
	switch {
	case cred.ClientID != "" && cred.ClientSecret != "":
		return CredentialOAuth
	case cred.ClientID != "" && (cred.IDToken != "" || cred.Audience != ""):
		return CredentialFederated
	case cred.Token != "":
		return CredentialBearer
	default:
		return CredentialUnknown
	}
}

func (c TailscaleCredential) validate() error {
	switch c.Kind {
	case CredentialOAuth:
		if c.ClientID == "" || c.ClientSecret == "" {
			return errors.New("oauth credential requires clientId and clientSecret")
		}
	case CredentialFederated:
		if c.ClientID == "" {
			return errors.New("federated credential requires clientId")
		}
		if c.IDToken == "" {
			return errors.New("federated credential requires idToken for Admin API access")
		}
	case CredentialBearer:
		if c.Token == "" {
			return errors.New("bearer credential requires token")
		}
	case CredentialUnknown:
		return errors.New("credential type is unknown")
	default:
		return fmt.Errorf("unsupported credential type %q", c.Kind)
	}
	return nil
}

func (c TailscaleCredential) AdminAuth() tsapi.Auth {
	switch c.Kind {
	case CredentialOAuth:
		return &tsapi.OAuth{ClientID: c.ClientID, ClientSecret: c.ClientSecret, Scopes: c.Scopes}
	case CredentialFederated:
		return &tsapi.IdentityFederation{ClientID: c.ClientID, IDTokenFunc: func() (string, error) { return c.IDToken, nil }}
	case CredentialBearer:
		return staticBearerAuth{Token: c.Token}
	default:
		return nil
	}
}

func (c TailscaleCredential) AdminHTTPClient(base *http.Client, baseURL string) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	auth := c.AdminAuth()
	if auth == nil {
		return base
	}
	return auth.HTTPClient(base, baseURL)
}

func (c TailscaleCredential) ConfigureTSNet(s *tsnet.Server) {
	switch c.Kind {
	case CredentialOAuth:
		s.ClientSecret = c.ClientSecret
	case CredentialFederated:
		s.ClientID = c.ClientID
		s.IDToken = c.IDToken
		s.Audience = c.Audience
	case CredentialBearer:
		s.AuthKey = c.Token
	}
}

func (c TailscaleCredential) RequiresTSNetAdvertiseTags() bool {
	switch c.Kind {
	case CredentialOAuth, CredentialFederated:
		return true
	case CredentialBearer:
		return strings.HasPrefix(c.Token, "tskey-client-")
	default:
		return false
	}
}

func parseAdvertiseTags(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	tags := make([]string, 0, len(parts))
	for _, part := range parts {
		tag := strings.TrimSpace(part)
		if tag == "" {
			continue
		}
		if !strings.HasPrefix(tag, "tag:") {
			return nil, fmt.Errorf("advertise tag %q must start with tag:", tag)
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

func tsnetStateDir(hostname string) string {
	hostname = strings.TrimSpace(strings.ToLower(hostname))
	if hostname == "" {
		hostname = mcpServerName
	}

	var b strings.Builder
	for _, r := range hostname {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "tsnet-" + mcpServerName
	}
	return "tsnet-" + b.String()
}

type tsnetStateConfig struct {
	Raw         string
	Dir         string
	StorePath   string
	Description string
}

func resolveTSNetState(raw, hostname string) (tsnetStateConfig, error) {
	raw = strings.TrimSpace(raw)
	defaultDir := tsnetStateDir(hostname)
	if raw == "" || raw == "file://" {
		return tsnetStateConfig{
			Raw:         raw,
			Dir:         defaultDir,
			Description: describeTSNetStateFile(defaultDir),
		}, nil
	}

	if strings.HasPrefix(raw, "file://") {
		dir := strings.TrimPrefix(raw, "file://")
		if strings.TrimSpace(dir) == "" || filepath.Clean(dir) == string(filepath.Separator) {
			return tsnetStateConfig{}, errors.New("file:// state requires a directory path or use file:// for the default")
		}
		return tsnetStateConfig{
			Raw:         raw,
			Dir:         dir,
			Description: describeTSNetStateFile(dir),
		}, nil
	}

	storePath, err := normalizeTSNetStateStore(raw)
	if err != nil {
		return tsnetStateConfig{}, err
	}
	return tsnetStateConfig{
		Raw:         raw,
		Dir:         defaultDir,
		StorePath:   storePath,
		Description: describeTSNetStateStore(storePath),
	}, nil
}

func normalizeTSNetStateStore(raw string) (string, error) {
	switch {
	case strings.HasPrefix(raw, "kube://"):
		secret := strings.TrimPrefix(raw, "kube://")
		if strings.TrimSpace(secret) == "" {
			return "", errors.New("kube:// state requires a Kubernetes Secret name")
		}
		return "kube:" + secret, nil
	case strings.HasPrefix(raw, "kube:"):
		if strings.TrimSpace(strings.TrimPrefix(raw, "kube:")) == "" {
			return "", errors.New("kube: state requires a Kubernetes Secret name")
		}
		return raw, nil
	case strings.HasPrefix(raw, "aws://"):
		return normalizeAWSState(raw)
	case strings.HasPrefix(raw, "arn:aws:ssm:"):
		return raw, nil
	case strings.HasPrefix(raw, "mem:"):
		return raw, nil
	default:
		return "", fmt.Errorf("unsupported TSNET_STATE %q; use file://, kube://, aws://, kube:, arn:aws:ssm:, or mem:", raw)
	}
}

func normalizeAWSState(raw string) (string, error) {
	rest := strings.TrimPrefix(raw, "aws://")
	if strings.HasPrefix(rest, "arn:aws:ssm:") {
		if strings.TrimSpace(rest) == "" {
			return "", errors.New("aws:// state requires an AWS SSM ARN")
		}
		return rest, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid aws:// state: %w", err)
	}
	region := u.Host
	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2)
	if region == "" || len(parts) != 2 || parts[0] == "" || !strings.HasPrefix(parts[1], "parameter/") {
		return "", errors.New("aws:// state must be aws://<region>/<account-id>/parameter/<name> or aws://arn:aws:ssm:<region>:<account-id>:parameter/<name>")
	}
	arn := fmt.Sprintf("arn:aws:ssm:%s:%s:%s", region, parts[0], parts[1])
	if u.RawQuery != "" {
		arn += "?" + u.RawQuery
	}
	return arn, nil
}

func describeTSNetStateFile(dir string) string {
	stateFile := filepath.Join(dir, "tailscaled.state")
	if abs, err := filepath.Abs(stateFile); err == nil {
		return "filesystem state file " + abs
	}
	return "filesystem state file " + stateFile
}

func describeTSNetStateStore(storePath string) string {
	switch {
	case strings.HasPrefix(storePath, "kube:"):
		return "Kubernetes Secret " + strings.TrimPrefix(storePath, "kube:")
	case strings.HasPrefix(storePath, "arn:aws:ssm:"):
		return "AWS SSM Parameter Store " + storePath
	case strings.HasPrefix(storePath, "mem:"):
		return "in-memory ephemeral tsnet state"
	default:
		return "tsnet state store " + storePath
	}
}

func tsnetZapLogf(log *zap.Logger, level zapcore.Level) func(format string, args ...any) {
	if log == nil {
		log = zap.NewNop()
	}
	return func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if ce := log.Check(level, msg); ce != nil {
			ce.Write(zap.String("component", "tsnet"))
		}
	}
}

func newTSNetServer(hostname string, advertiseTags []string, credential TailscaleCredential, debug bool, state tsnetStateConfig) (*tsnet.Server, error) {
	tsServer := &tsnet.Server{
		Dir:           state.Dir,
		Hostname:      hostname,
		AdvertiseTags: advertiseTags,
		UserLogf:      tsnetZapLogf(logger, zapcore.InfoLevel),
	}
	if debug {
		tsServer.Logf = tsnetZapLogf(logger, zapcore.DebugLevel)
	}
	if state.StorePath != "" {
		store, err := ipnstore.New(tsnetZapLogf(logger, zapcore.InfoLevel), state.StorePath)
		if err != nil {
			return nil, fmt.Errorf("failed to configure tsnet state store %q: %w", state.StorePath, err)
		}
		tsServer.Store = store
	}
	credential.ConfigureTSNet(tsServer)
	return tsServer, nil
}

func registerTSNetBuildInfo() {
	hostinfo.SetApp(mcpServerName)
	registerTSNetBuildInfoOnce.Do(func() {
		hostinfo.RegisterHostinfoNewHook(func(hi *tailcfg.Hostinfo) {
			hi.App = mcpServerName
			hi.IPNVersion = buildVersion
			hi.OS = mcpServerName
		})
	})
}

type staticBearerAuth struct {
	Token string
}

func (a staticBearerAuth) HTTPClient(orig *http.Client, _ string) *http.Client {
	transport := orig.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{
		Transport:     bearerRoundTripper{token: a.Token, base: transport},
		CheckRedirect: orig.CheckRedirect,
		Jar:           orig.Jar,
		Timeout:       orig.Timeout,
	}
}

type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (rt bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+rt.token)
	return rt.base.RoundTrip(clone)
}

func ValidateCredential(ctx context.Context, client *tsapi.Client) error {
	if _, err := client.TailnetSettings().Get(ctx); err != nil {
		return fmt.Errorf("failed to validate %s with tailnet settings read; verify the credential, tailnet, and required scopes: %w", tailscaleOAuthTokenEnv, err)
	}
	return nil
}

// MCPCapability represents MCP-specific capabilities from Tailscale grants
type MCPCapability struct {
	Tools     []string `json:"tools"`
	Resources []string `json:"resources"`
}

// PermissionError represents a structured permission error response
type PermissionError struct {
	Error       string            `json:"error"`
	Code        string            `json:"code"`
	Action      string            `json:"action"`
	Details     PermissionDetails `json:"details"`
	Suggestions []string          `json:"suggestions"`
}

// PermissionDetails provides context about the permission failure
type PermissionDetails struct {
	User               string   `json:"user"`
	RequestedItem      string   `json:"requested_item"`
	ItemType           string   `json:"item_type"` // "tool" or "resource"
	RequiredCapability string   `json:"required_capability"`
	UserCapabilities   []string `json:"user_capabilities,omitempty"`
}

// createPermissionErrorJSON creates a structured JSON error response for permission failures
func createPermissionErrorJSON(user, itemName, itemType string, userCapabilities []string) string {
	permError := PermissionError{
		Error:  "Permission denied",
		Code:   "INSUFFICIENT_PERMISSIONS",
		Action: "Contact your Tailscale administrator to request access",
		Details: PermissionDetails{
			User:               user,
			RequestedItem:      itemName,
			ItemType:           itemType,
			RequiredCapability: "jaxxstorm.com/cap/mcp",
			UserCapabilities:   userCapabilities,
		},
		Suggestions: []string{
			"Ask your Tailscale administrator to add MCP capabilities to your user account",
			fmt.Sprintf("Request access to the '%s' %s in your Tailscale ACL policy", itemName, itemType),
			"Verify you're authenticated with the correct Tailscale account",
			"Check if your organization has specific MCP access policies",
		},
	}

	jsonBytes, err := json.MarshalIndent(permError, "", "  ")
	if err != nil {
		// Fallback to simple error if JSON marshaling fails
		return `{"error": "Permission denied", "message": "Unable to format detailed error response"}`
	}

	return string(jsonBytes)
}

// initLogger initializes the Zap logger based on environment and debug settings
func initLogger(debug bool) {
	var config zap.Config

	// Check if we're running in a TTY
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))

	if isTTY {
		// Pretty console output for TTY
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05")
	} else {
		// Structured JSON output for non-TTY (production/logging systems)
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	// Set log level based on debug flag
	if debug {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	var err error
	logger, err = config.Build()
	if err != nil {
		log.Fatal("Failed to initialize logger:", err)
	}

	// Replace standard logger with zap
	zap.ReplaceGlobals(logger)
}

// getTailscaleCapabilities extracts MCP capabilities from the request context
func getTailscaleCapabilities(ctx context.Context) (*MCPCapability, string, error) {
	// The CapMap is actually tailcfg.PeerCapMap, but we can treat it as map[string]interface{}
	capMapRaw := ctx.Value("ts-grants")
	if capMapRaw == nil {
		return nil, "", fmt.Errorf("no tailscale grants found in context")
	}

	// Convert to map[string]interface{} - this should work regardless of the underlying type
	capBytes, err := json.Marshal(capMapRaw)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal capMap: %v", err)
	}

	var capMap map[string]interface{}
	if err := json.Unmarshal(capBytes, &capMap); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal capMap: %v", err)
	}

	userLogin, ok := ctx.Value("ts-user").(string)
	if !ok {
		userLogin = "unknown"
	}

	logger.Info("Checking capabilities",
		zap.String("user", userLogin),
		zap.Strings("grant_keys", func() []string {
			var keys []string
			for k := range capMap {
				keys = append(keys, k)
			}
			return keys
		}()),
	)

	// Look for jaxxstorm.com/cap/mcp capabilities
	if rawCaps, ok := capMap["jaxxstorm.com/cap/mcp"]; ok {
		logger.Debug("Found MCP capabilities", zap.Any("capabilities", rawCaps))

		// Marshal and unmarshal to handle the interface{} properly
		capBytes, err := json.Marshal(rawCaps)
		if err != nil {
			logger.Error("Failed to marshal capability", zap.Error(err))
			return nil, userLogin, fmt.Errorf("failed to marshal capability: %v", err)
		}

		logger.Debug("Capability JSON", zap.String("json", string(capBytes)))

		// Parse as array of MCPCapability (similar to TACLAppCapabilities pattern)
		var mcpCaps []MCPCapability
		if err := json.Unmarshal(capBytes, &mcpCaps); err != nil {
			logger.Debug("Failed to parse as array, trying single object", zap.Error(err))

			// Try parsing as single object
			var mcpCap MCPCapability
			if err := json.Unmarshal(capBytes, &mcpCap); err != nil {
				logger.Error("Failed to parse MCP capability", zap.Error(err))
				return nil, userLogin, fmt.Errorf("failed to parse MCP capability: %v", err)
			}

			logger.Info("Parsed single capability",
				zap.Strings("tools", mcpCap.Tools),
				zap.Strings("resources", mcpCap.Resources),
			)
			return &mcpCap, userLogin, nil
		}

		// If we successfully parsed as array, take the first one
		if len(mcpCaps) > 0 {
			logger.Info("Parsed array capability",
				zap.Strings("tools", mcpCaps[0].Tools),
				zap.Strings("resources", mcpCaps[0].Resources),
			)
			return &mcpCaps[0], userLogin, nil
		}
	}

	logger.Info("No MCP capabilities found")
	return nil, userLogin, nil
}

// checkToolAccess validates if the user has access to a specific tool
func checkToolAccess(ctx context.Context, toolName string) error {
	caps, user, err := getTailscaleCapabilities(ctx)
	if err != nil {
		logger.Error("Failed to get capabilities", zap.Error(err))
		errorJSON := createPermissionErrorJSON(user, toolName, "tool", []string{})
		return errors.New(errorJSON)
	}

	if caps == nil {
		logger.Warn("No MCP capabilities found", zap.String("user", user))
		errorJSON := createPermissionErrorJSON(user, toolName, "tool", []string{})
		return errors.New(errorJSON)
	}

	// Check if user has access to this specific tool
	for _, allowedTool := range caps.Tools {
		if allowedTool == "*" || allowedTool == toolName {
			logger.Info("Tool access granted",
				zap.String("user", user),
				zap.String("tool", toolName),
			)
			return nil
		}
	}

	logger.Warn("Tool access denied",
		zap.String("user", user),
		zap.String("tool", toolName),
		zap.Strings("allowed_tools", caps.Tools),
	)
	errorJSON := createPermissionErrorJSON(user, toolName, "tool", caps.Tools)
	return errors.New(errorJSON)
}

// checkResourceAccess validates if the user has access to a specific resource
func checkResourceAccess(ctx context.Context, resourceURI string) error {
	caps, user, err := getTailscaleCapabilities(ctx)
	if err != nil {
		logger.Error("Failed to get capabilities", zap.Error(err))
		errorJSON := createPermissionErrorJSON(user, resourceURI, "resource", []string{})
		return errors.New(errorJSON)
	}

	if caps == nil {
		logger.Warn("No MCP capabilities found", zap.String("user", user))
		errorJSON := createPermissionErrorJSON(user, resourceURI, "resource", []string{})
		return errors.New(errorJSON)
	}

	// Check if user has access to this specific resource
	for _, allowedResource := range caps.Resources {
		if allowedResource == "*" || allowedResource == resourceURI || strings.HasPrefix(resourceURI, allowedResource) {
			logger.Info("Resource access granted",
				zap.String("user", user),
				zap.String("resource", resourceURI),
			)
			return nil
		}
	}

	logger.Warn("Resource access denied",
		zap.String("user", user),
		zap.String("resource", resourceURI),
		zap.Strings("allowed_resources", caps.Resources),
	)
	errorJSON := createPermissionErrorJSON(user, resourceURI, "resource", caps.Resources)
	return errors.New(errorJSON)
}

// loggingMiddleware logs all incoming requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("HTTP Request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("user_agent", r.Header.Get("User-Agent")),
		)

		// Log additional headers for debugging
		if sessionID := r.Header.Get("Mcp-Session-Id"); sessionID != "" {
			logger.Debug("MCP Session", zap.String("session_id", sessionID))
		}
		if user := r.Header.Get("X-Tailscale-User"); user != "" {
			logger.Debug("Tailscale User", zap.String("user", user))
		}
		if node := r.Header.Get("X-Tailscale-Node"); node != "" {
			logger.Debug("Tailscale Node", zap.String("node", node))
		}

		next.ServeHTTP(w, r)
	})
}

func allowOriginMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && !strings.HasPrefix(origin, "http://"+r.Host) && !strings.HasPrefix(origin, "https://"+r.Host) {
			logger.Warn("Forbidden origin", zap.String("origin", origin))
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func streamableHTTPHandler(streamable http.Handler, tsServer *tsnet.Server) http.Handler {
	return loggingMiddleware(allowOriginMiddleware(grantMiddleware(streamable, tsServer)))
}

func main() {
	var cli CLI
	kong.Parse(&cli)

	// Initialize logger early
	initLogger(cli.Debug)
	defer logger.Sync()

	if cli.Version {
		fmt.Println("ts-mcp", buildVersion)
		return
	}

	logger.Info("Starting ts-mcp",
		zap.String("version", buildVersion),
		zap.String("tailnet", cli.Tailnet),
		zap.String("hostname", cli.Hostname),
		zap.Int("port", cli.Port),
		zap.Bool("debug", cli.Debug),
		zap.Bool("stdio", cli.Stdio),
	)
	credential, err := ParseTailscaleCredentialWithClientID(cli.Credential, cli.OAuthClientID)
	if err != nil {
		logger.Fatal("Invalid Tailscale credential configuration", zap.Error(err))
	}
	advertiseTags, err := parseAdvertiseTags(cli.AdvertiseTags)
	if err != nil {
		logger.Fatal("Invalid Tailscale advertise tags", zap.Error(err))
	}
	stateConfig, err := resolveTSNetState(cli.State, cli.Hostname)
	if err != nil {
		logger.Fatal("Invalid tsnet state configuration", zap.Error(err), zap.String("env", "TSNET_STATE"))
	}
	if credential.RequiresTSNetAdvertiseTags() && len(advertiseTags) == 0 {
		logger.Fatal("Tailscale credential requires advertised tags for tsnet startup",
			zap.String("env", "TS_ADVERTISE_TAGS"),
			zap.String("example", "tag:mcp-server"),
		)
	}
	logger.Info("Configured Tailscale credential", zap.String("credential_type", string(credential.Kind)))
	logger.Info("Configured tsnet state",
		zap.String("location", stateConfig.Description),
		zap.String("dir", stateConfig.Dir),
		zap.String("store", stateConfig.StorePath),
	)

	tsAdminClient := &tsapi.Client{
		Tailnet: cli.Tailnet,
		Auth:    credential.AdminAuth(),
	}
	readAPIClient := readapi.Client{
		Tailnet:    cli.Tailnet,
		HTTPClient: credential.AdminHTTPClient(nil, "https://api.tailscale.com"),
	}
	if err := ValidateCredential(context.Background(), tsAdminClient); err != nil {
		logger.Fatal("Tailscale credential validation failed", zap.Error(err))
	}

	mcpServer := server.NewMCPServer(mcpServerName, buildVersion)

	registerCoreMCP(mcpServer, tsAdminClient)
	readapi.RegisterTools(mcpServer, readAPIClient, checkToolAccess)
	readapi.RegisterResources(mcpServer, readAPIClient, checkResourceAccess)
	curatedtools.RegisterAll(mcpServer, curatedtools.Options{Client: readAPIClient, Check: checkToolAccess, LocalCLI: cli.LocalCLI})

	// Deprecated stdio compatibility mode.
	if cli.Stdio {
		logger.Warn("Stdio transport is deprecated; use Streamable HTTP instead",
			zap.String("transport", "stdio"),
			zap.String("recommended_transport", streamableHTTPTransportName),
			zap.String("recommended_endpoint", mcpEndpointPath),
		)
		logger.Info("Starting deprecated MCP stdio transport")
		if err := server.ServeStdio(mcpServer); err != nil {
			logger.Fatal("Stdio server error", zap.Error(err))
		}
		os.Exit(0)
	}
	if err := os.Setenv("TSNET_FORCE_LOGIN", strconv.FormatBool(cli.ForceLogin)); err != nil {
		logger.Fatal("Failed to configure tsnet force login", zap.Error(err))
	}
	if cli.ForceLogin {
		logger.Info("Forcing tsnet login with supplied startup credential", zap.String("env", "TSNET_FORCE_LOGIN"))
	}

	registerTSNetBuildInfo()
	tsServer, err := newTSNetServer(cli.Hostname, advertiseTags, credential, cli.Debug, stateConfig)
	if err != nil {
		logger.Fatal("Failed to configure tsnet server", zap.Error(err))
	}
	defer tsServer.Close()

	tsLn, err := tsServer.Listen("tcp", fmt.Sprintf(":%d", cli.Port))
	if err != nil {
		logger.Fatal("tsnet listen error", zap.Error(err))
	}
	logger.Info("Serving MCP via Tailscale",
		zap.String("transport", streamableHTTPTransportName),
		zap.String("address", tsLn.Addr().String()),
		zap.String("endpoint", mcpEndpointPath),
	)

	streamable := server.NewStreamableHTTPServer(
		mcpServer,
		server.WithEndpointPath(mcpEndpointPath),
	)

	mux := http.NewServeMux()
	mux.Handle(mcpEndpointPath, streamableHTTPHandler(streamable, tsServer))

	handlerWithMiddleware := mux

	go func() {
		logger.Info("Serving MCP locally",
			zap.String("transport", streamableHTTPTransportName),
			zap.String("address", defaultLocalStreamableAddr),
			zap.String("endpoint", mcpEndpointPath),
		)
		if err := http.ListenAndServe(defaultLocalStreamableAddr, handlerWithMiddleware); err != nil {
			logger.Fatal("Local server error", zap.Error(err))
		}
	}()

	if err := http.Serve(tsLn, handlerWithMiddleware); err != nil {
		logger.Fatal("Tailscale server error", zap.Error(err))
	}
}

func registerCoreMCP(mcpServer *server.MCPServer, tsAdminClient *tsapi.Client) {
	logger.Debug("Adding prompts capability")
	mcpServer.AddPrompt(mcp.NewPrompt("empty"),
		func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{Messages: []mcp.PromptMessage{}}, nil
		})

	mcpServer.AddResource(mcp.NewResource("bootstrap://status", "Health-check", mcp.WithMIMEType("text/plain")),
		func(ctx context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			logger.Debug("Resource requested", zap.String("resource", "bootstrap://status"))
			if err := checkResourceAccess(ctx, "bootstrap://status"); err != nil {
				return nil, err
			}
			return []mcp.ResourceContents{mcp.TextResourceContents{URI: "bootstrap://status", MIMEType: "text/plain", Text: "up"}}, nil
		})

	mcpServer.AddResource(mcp.NewResource("tailscale://devices", "List all devices in the tailnet", mcp.WithMIMEType("application/json")),
		func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			logger.Debug("Resource requested", zap.String("resource", "tailscale://devices"))
			if err := checkResourceAccess(ctx, "tailscale://devices"); err != nil {
				return nil, err
			}

			devices, err := tsAdminClient.Devices().ListWithAllFields(ctx)
			if err != nil {
				logger.Error("Failed to list devices", zap.Error(err))
				return nil, err
			}
			data, err := json.MarshalIndent(devices, "", "  ")
			if err != nil {
				logger.Error("Failed to marshal devices", zap.Error(err))
				return nil, err
			}

			logger.Info("Retrieved devices", zap.Int("count", len(devices)))
			return []mcp.ResourceContents{mcp.TextResourceContents{URI: "tailscale://devices", MIMEType: "application/json", Text: string(data)}}, nil
		})

	mcpServer.AddResource(mcp.NewResource("tailscale://policy", "Fetch the current Tailscale policy file (ACL)", mcp.WithMIMEType("application/json")),
		func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			logger.Debug("Resource requested", zap.String("resource", "tailscale://policy"))
			if err := checkResourceAccess(ctx, "tailscale://policy"); err != nil {
				return nil, err
			}

			policy, err := tsAdminClient.PolicyFile().Raw(ctx)
			if err != nil {
				logger.Error("Failed to fetch policy file", zap.Error(err))
				return nil, fmt.Errorf("failed to fetch policy file: %w", err)
			}
			parsed, err := hujson.Parse([]byte(policy.HuJSON))
			if err != nil {
				logger.Error("Failed to parse HuJSON policy file", zap.Error(err))
				return nil, fmt.Errorf("failed to parse HuJSON policy file: %w", err)
			}
			parsed.Standardize()

			var standardizedPolicy interface{}
			if err := json.Unmarshal(parsed.Pack(), &standardizedPolicy); err != nil {
				logger.Error("Failed to unmarshal standardized policy JSON", zap.Error(err))
				return nil, fmt.Errorf("failed to unmarshal standardized policy JSON: %w", err)
			}
			data, err := json.MarshalIndent(standardizedPolicy, "", "  ")
			if err != nil {
				logger.Error("Failed to marshal standardized policy JSON", zap.Error(err))
				return nil, fmt.Errorf("failed to marshal standardized policy JSON: %w", err)
			}

			logger.Info("Retrieved policy file")
			return []mcp.ResourceContents{mcp.TextResourceContents{URI: "tailscale://policy", MIMEType: "application/json", Text: string(data)}}, nil
		})

	mcpServer.AddResource(mcp.NewResource("tailscale://tailnet-settings", "Tailnet Settings", mcp.WithMIMEType("application/json")),
		func(ctx context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			logger.Debug("Resource requested", zap.String("resource", "tailscale://tailnet-settings"))
			if err := checkResourceAccess(ctx, "tailscale://tailnet-settings"); err != nil {
				return nil, err
			}

			settings, err := tsAdminClient.TailnetSettings().Get(ctx)
			if err != nil {
				logger.Error("Failed to fetch tailnet settings", zap.Error(err))
				return nil, fmt.Errorf("failed to fetch tailnet settings: %w", err)
			}
			data, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				logger.Error("Failed to marshal tailnet settings", zap.Error(err))
				return nil, fmt.Errorf("failed to marshal tailnet settings: %w", err)
			}

			logger.Info("Retrieved tailnet settings")
			return []mcp.ResourceContents{mcp.TextResourceContents{URI: "tailscale://tailnet-settings", MIMEType: "application/json", Text: string(data)}}, nil
		})

	mcpServer.AddResource(mcp.NewResource("tailscale://device", "Query device details by ID or hostname", mcp.WithMIMEType("application/json")),
		func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			deviceID, ok := req.Params.Arguments["device"].(string)
			if !ok || deviceID == "" {
				logger.Error("Device parameter required for tailscale://device")
				return nil, fmt.Errorf("device parameter required")
			}
			logger.Debug("Resource requested", zap.String("resource", "tailscale://device"), zap.String("device_id", deviceID))

			if err := checkResourceAccess(ctx, "tailscale://device"); err != nil {
				return nil, err
			}
			device, err := findDevice(ctx, tsAdminClient, deviceID)
			if err != nil {
				logger.Error("Failed to find device", zap.String("device_id", deviceID), zap.Error(err))
				return nil, err
			}
			data, err := json.MarshalIndent(device, "", "  ")
			if err != nil {
				logger.Error("Failed to marshal device", zap.String("device_id", deviceID), zap.Error(err))
				return nil, err
			}

			logger.Info("Retrieved device", zap.String("device_id", deviceID))
			return []mcp.ResourceContents{mcp.TextResourceContents{URI: fmt.Sprintf("tailscale://device/%s", deviceID), MIMEType: "application/json", Text: string(data)}}, nil
		})

	mcpServer.AddTool(mcp.NewTool("get_device_info",
		mcp.WithDescription("Fetch device details by ID, IP, or hostname"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithString("device", mcp.Required(), mcp.Description("Device ID, IP, or hostname")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger.Debug("Tool called", zap.String("tool", "get_device_info"))
		if err := checkToolAccess(ctx, "get_device_info"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			logger.Error("Invalid arguments format for get_device_info")
			return mcp.NewToolResultError("invalid arguments format"), nil
		}
		deviceID := args["device"].(string)
		logger.Debug("Tool parameters", zap.String("device_id", deviceID))

		device, err := findDevice(ctx, tsAdminClient, deviceID)
		if err != nil {
			logger.Error("Device lookup failed", zap.String("device_id", deviceID), zap.Error(err))
			return mcp.NewToolResultErrorFromErr("Device lookup failed", err), nil
		}
		data, err := json.MarshalIndent(device, "", "  ")
		if err != nil {
			logger.Error("JSON marshal failed", zap.String("device_id", deviceID), zap.Error(err))
			return mcp.NewToolResultErrorFromErr("JSON marshal failed", err), nil
		}
		logger.Info("Tool executed successfully", zap.String("tool", "get_device_info"), zap.String("device_id", deviceID))
		return mcp.NewToolResultText(string(data)), nil
	})

	mcpServer.AddTool(mcp.NewTool("list_all_devices",
		mcp.WithDescription("List all devices in the tailnet"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
	),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			logger.Debug("Tool called", zap.String("tool", "list_all_devices"))
			if err := checkToolAccess(ctx, "list_all_devices"); err != nil {
				return mcp.NewToolResultText(err.Error()), nil
			}

			devices, err := tsAdminClient.Devices().List(ctx)
			if err != nil {
				logger.Error("Failed to list devices", zap.Error(err))
				return mcp.NewToolResultErrorFromErr("Failed to list devices", err), nil
			}
			data, err := json.MarshalIndent(devices, "", "  ")
			if err != nil {
				logger.Error("JSON marshal failed", zap.Error(err))
				return mcp.NewToolResultErrorFromErr("JSON marshal failed", err), nil
			}

			logger.Info("Tool executed successfully", zap.String("tool", "list_all_devices"), zap.Int("device_count", len(devices)))
			return mcp.NewToolResultText(string(data)), nil
		})
}

// findDevice finds a device by ID, hostname, or IP and fetches detailed information.
func findDevice(ctx context.Context, client *tsapi.Client, id string) (*tsapi.Device, error) {
	devices, err := client.Devices().List(ctx)
	if err != nil {
		return nil, err
	}

	for _, d := range devices {
		if d.ID == id || d.Hostname == id {
			return client.Devices().GetWithAllFields(ctx, d.ID)
		}
		for _, addr := range d.Addresses {
			if addr == id {
				return client.Devices().GetWithAllFields(ctx, d.ID)
			}
		}
	}

	return nil, fmt.Errorf("device not found: %s", id)
}

// OAuth Grants Middleware
func grantMiddleware(next http.Handler, tsServer *tsnet.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse IP from remote address
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			logger.Error("Failed to parse IP from RemoteAddr", zap.Error(err))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Get the LocalClient from tsnet server
		tsLocalClient, err := tsServer.LocalClient()
		if err != nil {
			logger.Error("Failed to get LocalClient", zap.Error(err))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		who, err := tsLocalClient.WhoIs(r.Context(), ip)
		if err != nil {
			logger.Error("WhoIs error", zap.String("ip", ip), zap.Error(err))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		userLoginName := ""
		if who.UserProfile != nil {
			userLoginName = who.UserProfile.LoginName
		}

		logger.Info("Authorized user",
			zap.String("user", userLoginName),
			zap.String("ip", ip),
		)
		logger.Debug("User capabilities",
			zap.String("user", userLoginName),
			zap.Any("cap_map", who.CapMap),
		)

		// Add both grants and user info to context using the correct types
		ctx := context.WithValue(r.Context(), "ts-grants", who.CapMap)
		ctx = context.WithValue(ctx, "ts-user", userLoginName)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
