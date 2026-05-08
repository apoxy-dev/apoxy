package config

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"
	"github.com/pkg/browser"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/apoxy-dev/apoxy/web"
)

type authContext struct {
	APIKey    string
	ProjectID uuid.UUID
}

type Authenticator struct {
	cfg        *configv1alpha1.Config
	authCh     chan authContext
	apiBaseURL string // optional override
}

// AuthenticatorOption is a functional option for configuring the Authenticator.
type AuthenticatorOption func(*Authenticator)

// WithAPIBaseURL sets the API base URL for the authenticated project.
func WithAPIBaseURL(url string) AuthenticatorOption {
	return func(a *Authenticator) {
		a.apiBaseURL = url
	}
}

func NewAuthenticator(cfg *configv1alpha1.Config, opts ...AuthenticatorOption) *Authenticator {
	a := &Authenticator{
		cfg: cfg,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// ErrUnauthenticated is returned by Check when the server explicitly rejects
// the credentials (HTTP 401/403). Other errors mean the check could not be
// completed (network, missing config, server error).
var ErrUnauthenticated = errors.New("not authenticated")

func (a *Authenticator) Check() error {
	log.Debugf("Checking Apoxy authentication")
	c, err := DefaultAPIClient()
	if err != nil {
		return err
	}

	if c.BaseHost != "" {
		resp, err := c.SendRequest(http.MethodPost, "/v1/terra/check", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		log.Debugf("/v1/terra/check returned status=%d", resp.StatusCode)
		switch resp.StatusCode {
		case http.StatusOK:
			return nil
		case http.StatusUnauthorized, http.StatusForbidden:
			return ErrUnauthenticated
		default:
			return fmt.Errorf("/v1/terra/check returned status %d", resp.StatusCode)
		}
	}

	_, err = c.Discovery().ServerVersion()
	return err
}
func (a *Authenticator) healthzHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "OK")
}

func (a *Authenticator) handler(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	projectID := r.URL.Query().Get("project")
	log.Debugf("API key received. APIKey=%q ProjectID=%q", key, projectID)
	go func() {
		time.Sleep(2 * time.Second)
		pUUID, err := uuid.Parse(projectID)
		if err != nil {
			slog.Error("Failed to parse project ID: %v", err)
			return
		}
		a.authCh <- authContext{APIKey: key, ProjectID: pUUID}
	}()
	fmt.Fprintf(w, web.LoginOKHTML)
}

func (a *Authenticator) awaitHealthy(port int) error {
	url := fmt.Sprintf("http://localhost:%d/healthz", port)
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	attempt := 0
	for {
		resp, err := client.Get(url)
		if err == nil {
			defer resp.Body.Close()
			break
		}
		time.Sleep(1 * time.Second)
		attempt++
		if attempt > 10 {
			return fmt.Errorf("Failed to health check server")
		}
	}
	return nil
}

func (a *Authenticator) launchServer() int {
	// Create a listener on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Error starting listener: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		defer listener.Close()
		http.HandleFunc("/", a.handler)
		http.HandleFunc("/healthz", a.healthzHandler)
		log.Debugf("Server listening on port %d", port)
		err = http.Serve(listener, nil)
		if err != nil {
			log.Errorf("Error starting server: %v", err)
		}
	}()
	if err := a.awaitHealthy(port); err != nil {
		log.Errorf("Error starting server: %v", err)
		sentry.CaptureMessage("auth redirect server failed to start")
	}
	return port
}

func (a *Authenticator) Authenticate() {
	a.authCh = make(chan authContext)
	port := a.launchServer()
	next := url.QueryEscape(fmt.Sprintf("http://localhost:%d/auth", port))
	log.Debugf("Using config: DashboardURL=%q", a.cfg.DashboardURL)
	host := a.cfg.DashboardURL
	if host == "" {
		host = DefaultConfig.DashboardURL
		log.Debugf("Using default dashboard URL: %q", host)
	}
	authUrl := fmt.Sprintf("%s/auth/cli?redirect=%s", host, next)
	browser.OpenURL(authUrl)
	fmt.Println("If a browser window did not open, you may authenticate using the following URL:")
	fmt.Printf("\n\t%s\n\n", authUrl)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case key := <-a.authCh:
		var projectUpdated bool
		for i, p := range a.cfg.Projects {
			if p.ID == a.cfg.CurrentProject {
				a.cfg.Projects[i].APIKey = key.APIKey
				a.cfg.Projects[i].ID = key.ProjectID
				if a.apiBaseURL != "" {
					a.cfg.Projects[i].APIBaseURL = a.apiBaseURL
				}
				projectUpdated = true
				break
			}
		}
		if !projectUpdated {
			newProject := configv1alpha1.Project{
				ID:     key.ProjectID,
				APIKey: key.APIKey,
			}
			if a.apiBaseURL != "" {
				newProject.APIBaseURL = a.apiBaseURL
			}
			a.cfg.Projects = append(a.cfg.Projects, newProject)
			log.Debugf("Appended new project. ProjectID=%q", key.ProjectID)
		}
		a.cfg.CurrentProject = key.ProjectID

		log.Debugf("API key set. APIKey=%q ProjectID=%q", key.APIKey, a.cfg.CurrentProject)
		fmt.Println("Login Succcessful!")
	case <-sigCh:
		log.Errorf("Authentication cancelled by user")
		return
	}
}
