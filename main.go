package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	githubAuthURL  = "https://github.com/login/oauth/authorize"
	githubTokenURL = "https://github.com/login/oauth/access_token"
	githubAPIURL   = "https://api.github.com"
)

type Config struct {
	ClientID     string
	ClientSecret string
	Port         string
}

type GitHubClient struct {
	accessToken string
	httpClient  *http.Client
}

type DeployKey struct {
	Title    string `json:"title"`
	Key      string `json:"key"`
	ReadOnly bool   `json:"read_only"`
}

type DeployKeyResponse struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Key   string `json:"key"`
	URL   string `json:"url"`
}

func main() {
	var (
		clientID     = flag.String("client-id", "", "GitHub OAuth App Client ID")
		clientSecret = flag.String("client-secret", "", "GitHub OAuth App Client Secret")
		port         = flag.String("port", "8080", "Local server port for OAuth callback")
		repo         = flag.String("repo", "", "Repository in format 'owner/repo'")
		keyTitle     = flag.String("title", "", "Title for the deploy key")
		readOnly     = flag.Bool("read-only", false, "Create read-only deploy key (default: false, i.e., write access)")
		writeAccess  = flag.Bool("write", false, "Create deploy key with write access (overrides -read-only)")
		help         = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		printHelp()
		return
	}

	// Check for required parameters
	if *clientID == "" || *clientSecret == "" || *repo == "" || *keyTitle == "" {
		fmt.Println("Error: Missing required parameters")
		printHelp()
		os.Exit(1)
	}

	config := &Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		Port:         *port,
	}

	// Determine if key should be read-only
	// If -write flag is set, it overrides -read-only
	isReadOnly := *readOnly
	if *writeAccess {
		isReadOnly = false
	}

	fmt.Println("🚀 GitHub Deploy Key CLI Tool")
	fmt.Println("==============================")

	// Step 1: Generate SSH key pair
	fmt.Println("📝 Generating SSH key pair...")
	publicKey, privateKey, err := generateSSHKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate SSH key pair: %v", err)
	}

	// Step 2: Start OAuth flow
	fmt.Println("🔐 Starting OAuth authentication...")
	client, err := authenticateWithGitHub(config)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	// Step 3: Create deploy key
	accessType := "read-only"
	if !isReadOnly {
		accessType = "read-write"
	}
	fmt.Printf("🔑 Creating %s deploy key '%s' for repository '%s'...\n", accessType, *keyTitle, *repo)
	deployKey, err := client.createDeployKey(*repo, *keyTitle, publicKey, isReadOnly)
	if err != nil {
		log.Fatalf("Failed to create deploy key: %v", err)
	}

	// Step 4: Save private key to file
	keyFileName := fmt.Sprintf("%s_deploy_key", strings.ReplaceAll(*keyTitle, " ", "_"))
	err = savePrivateKey(keyFileName, privateKey)
	if err != nil {
		log.Fatalf("Failed to save private key: %v", err)
	}

	// Step 5: Update SSH config
	fmt.Println("🔧 Updating SSH config...")
	repoName := extractRepoName(*repo)
	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current directory: %v", err)
	}
	keyPath := filepath.Join(currentDir, keyFileName)

	err = updateSSHConfig(repoName, keyPath)
	if err != nil {
		log.Printf("⚠️  Warning: Failed to update SSH config: %v", err)
		log.Println("   You can manually add the SSH config entry.")
	} else {
		fmt.Println("✅ SSH config updated successfully!")
	}

	// Success message
	fmt.Println("\n✅ Deploy key created successfully!")
	fmt.Printf("   📋 Key ID: %d\n", deployKey.ID)
	fmt.Printf("   📝 Title: %s\n", deployKey.Title)
	fmt.Printf("   📁 Private key saved to: %s\n", keyFileName)
	fmt.Printf("   🔗 GitHub URL: %s\n", deployKey.URL)
	if isReadOnly {
		fmt.Printf("   🔒 Access: Read-only\n")
	} else {
		fmt.Printf("   ✍️  Access: Read-write\n")
	}

	fmt.Println("\n📋 Usage Instructions:")
	fmt.Println("   Add this to your CI/CD or deployment configuration:")
	fmt.Printf("   ssh-add %s\n", keyFileName)
	fmt.Printf("   git clone git@github.com-%s:%s.git\n", repoName, *repo)
}

func printHelp() {
	fmt.Println("GitHub Deploy Key CLI Tool")
	fmt.Println("==========================")
	fmt.Println()
	fmt.Println("This tool creates a GitHub deploy key using OAuth authentication.")
	fmt.Println()
	fmt.Println("Prerequisites:")
	fmt.Println("  1. Create a GitHub OAuth App at https://github.com/settings/applications/new")
	fmt.Println("  2. Set Authorization callback URL to: http://localhost:8080/callback")
	fmt.Println("     (or your custom port)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  go run main.go [options]")
	fmt.Println()
	fmt.Println("Required flags:")
	fmt.Println("  -client-id string     GitHub OAuth App Client ID")
	fmt.Println("  -client-secret string GitHub OAuth App Client Secret")
	fmt.Println("  -repo string          Repository in format 'owner/repo'")
	fmt.Println("  -title string         Title for the deploy key")
	fmt.Println()
	fmt.Println("Optional flags:")
	fmt.Println("  -port string          Local server port (default: 8080)")
	fmt.Println("  -write                Create deploy key with write access (default: false)")
	fmt.Println("  -read-only            Create read-only deploy key (default: false)")
	fmt.Println("  -help                 Show this help")
	fmt.Println()
	fmt.Println("Note: By default, deploy keys are created with write access.")
	fmt.Println("      Use -read-only flag to create a read-only key.")
	fmt.Println("      Use -write flag to explicitly enable write access.")
	fmt.Println()
	fmt.Println("Example (write access):")
	fmt.Println("  go run main.go \\")
	fmt.Println("    -client-id=your_client_id \\")
	fmt.Println("    -client-secret=your_client_secret \\")
	fmt.Println("    -repo=owner/repository \\")
	fmt.Println("    -title=\"Production Deploy Key\" \\")
	fmt.Println("    -write")
	fmt.Println()
	fmt.Println("Example (read-only access):")
	fmt.Println("  go run main.go \\")
	fmt.Println("    -client-id=your_client_id \\")
	fmt.Println("    -client-secret=your_client_secret \\")
	fmt.Println("    -repo=owner/repository \\")
	fmt.Println("    -title=\"Read-Only Deploy Key\" \\")
	fmt.Println("    -read-only")
}

func generateSSHKeyPair() (string, string, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate public key in SSH format
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate public key: %w", err)
	}

	// Format public key
	publicKeyStr := string(ssh.MarshalAuthorizedKey(publicKey))
	publicKeyStr = strings.TrimSpace(publicKeyStr)

	// Format private key in PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyStr := string(pem.EncodeToMemory(privateKeyPEM))

	return publicKeyStr, privateKeyStr, nil
}

func authenticateWithGitHub(config *Config) (*GitHubClient, error) {
	// Create a channel to receive the authorization code
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)

	// Start local server for OAuth callback
	server := &http.Server{Addr: ":" + config.Port}

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			errChan <- fmt.Errorf("no authorization code received")
			return
		}

		fmt.Fprintf(w, `
			<html>
				<head><title>GitHub OAuth</title></head>
				<body>
					<h1>✅ Authorization successful!</h1>
					<p>You can close this window and return to the CLI.</p>
				</body>
			</html>
		`)

		codeChan <- code
	})

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			errChan <- fmt.Errorf("server error: %w", err)
		}
	}()

	// Build authorization URL
	authURL := fmt.Sprintf("%s?client_id=%s&scope=repo&redirect_uri=%s",
		githubAuthURL,
		config.ClientID,
		url.QueryEscape(fmt.Sprintf("http://localhost:%s/callback", config.Port)),
	)

	fmt.Printf("🌐 Opening browser for GitHub authorization...\n")
	fmt.Printf("   If browser doesn't open, visit: %s\n", authURL)

	// Open browser
	if err := openBrowser(authURL); err != nil {
		fmt.Printf("⚠️  Could not open browser automatically: %v\n", err)
		fmt.Printf("   Please open the following URL manually:\n   %s\n", authURL)
	}

	// Wait for authorization code or timeout
	var code string
	select {
	case code = <-codeChan:
		// Success
	case err := <-errChan:
		return nil, err
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("timeout waiting for authorization")
	}

	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)

	// Exchange athorization code for access token
	fmt.Println("🔄 Exchanging authorization code for access token...")
	accessToken, err := exchangeCodeForToken(config, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	return &GitHubClient{
		accessToken: accessToken,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func exchangeCodeForToken(config *Config, code string) (string, error) {
	data := url.Values{}
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)
	data.Set("code", code)

	req, err := http.NewRequest("POST", githubTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	if tokenResp.Error != "" {
		return "", fmt.Errorf("GitHub OAuth error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("no access token received")
	}

	return tokenResp.AccessToken, nil
}

func (c *GitHubClient) createDeployKey(repo, title, publicKey string, readOnly bool) (*DeployKeyResponse, error) {
	deployKey := DeployKey{
		Title:    title,
		Key:      publicKey,
		ReadOnly: readOnly,
	}

	jsonData, err := json.Marshal(deployKey)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/repos/%s/keys", githubAPIURL, repo)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		// Capture raw response body to aid debugging of 4xx/5xx errors.
		rawBody, _ := io.ReadAll(resp.Body)
		var errorResp struct {
			Message          string           `json:"message"`
			DocumentationURL string           `json:"documentation_url"`
			Errors           []map[string]any `json:"errors"`
		}
		_ = json.Unmarshal(rawBody, &errorResp)

		log.Printf("Deploy key creation failed. repo=%q status=%d url=%q", repo, resp.StatusCode, url)
		if len(rawBody) > 0 {
			log.Printf("GitHub API response body: %s", strings.TrimSpace(string(rawBody)))
		}
		if errorResp.Message != "" {
			log.Printf("GitHub API message: %s", errorResp.Message)
		}
		if errorResp.DocumentationURL != "" {
			log.Printf("GitHub API docs: %s", errorResp.DocumentationURL)
		}
		if len(errorResp.Errors) > 0 {
			log.Printf("GitHub API errors: %+v", errorResp.Errors)
		}

		return nil, fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, errorResp.Message)
	}

	var deployKeyResp DeployKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&deployKeyResp); err != nil {
		return nil, err
	}

	return &deployKeyResp, nil
}

func savePrivateKey(fileName, privateKey string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	// Set restrictive permissions (600 - owner read/write only)
	if err := file.Chmod(0600); err != nil {
		return err
	}

	_, err = file.WriteString(privateKey)
	return err
}

func extractRepoName(repo string) string {
	// Extract repository name from "owner/repo" format
	parts := strings.Split(repo, "/")
	if len(parts) == 2 {
		return parts[1]
	}
	return repo
}

func updateSSHConfig(repoName, keyPath string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	sshConfigPath := filepath.Join(homeDir, ".ssh", "config")

	// Read existing config file if it exists
	var existingContent string
	if data, err := os.ReadFile(sshConfigPath); err == nil {
		existingContent = string(data)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read SSH config: %w", err)
	}

	// Check if this host entry already exists
	hostEntry := fmt.Sprintf("Host github.com-%s", repoName)
	if strings.Contains(existingContent, hostEntry) {
		log.Printf("SSH config entry for %s already exists, skipping update", repoName)
		return nil
	}

	// Create the new SSH config entry
	newEntry := fmt.Sprintf("\nHost github.com-%s\n  Hostname github.com\n  User bldmgr\n  IdentityFile=%s\n  IdentitiesOnly yes\n",
		repoName, keyPath)

	// Ensure .ssh directory exists
	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Append to SSH config
	file, err := os.OpenFile(sshConfigPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open SSH config: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(newEntry); err != nil {
		return fmt.Errorf("failed to write to SSH config: %w", err)
	}

	return nil
}

func openBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return fmt.Errorf("unsupported platform")
	}

	return cmd.Start()
}
