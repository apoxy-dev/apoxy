package apiserviceproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var systemCertPool = x509.SystemCertPool

const (
	// Default Cosmos API host.
	defaultAPIHost = "api.apoxy.dev"
	// APIServer APIs.
	defaultAPIProxyHost      = "apiz.apoxy.dev"
	kubeControllerUserPrefix = "kube-controller-"

	apizCertSecretName          = "apiz-cert"
	apiServiceServingSecretName = "apiservice-serving-cert"
	tlsSecretCert               = "tls.crt"
	tlsSecretKey                = "tls.key"
	tlsSecretCA                 = "ca.crt"

	// Apoxy API headers.
	ApoxyAPIKeyHeaderKey    = "x-apoxy-api-key"
	ApoxyProjectIdHeaderKey = "x-apoxy-project-id"
	ApoxyServiceUserKey     = "x-apoxy-service-user"
)

// IssueClientCertResponse is the response from the certificate issuance endpoint.
// Field names use camelCase to match gRPC-gateway's default protojson output.
type IssueClientCertResponse struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
	CA          string `json:"ca"`
}

func (p *APIServiceProxy) configureCloudProxy(ctx context.Context) error {
	log.Printf("configuring cloud proxy for project %s", p.opts.ProjectID)

	remote, err := url.Parse(fmt.Sprintf("https://%s", resolveAPIProxyHost(p.opts.ProjectID, p.opts.APIHost)))
	if err != nil {
		return fmt.Errorf("failed to parse remote URL: %w", err)
	}
	p.proxy = newCloudReverseProxy(remote)

	if err := p.ensureServingCertificate(ctx); err != nil {
		return fmt.Errorf("failed to ensure serving certificate: %w", err)
	}

	ok, err := p.loadUpstreamCertificate(ctx)
	if err != nil {
		log.Printf("existing upstream certificate is invalid, re-issuing: %v", err)
		ok = false
	}
	if !ok {
		if err := p.issueCertificate(ctx); err != nil {
			return fmt.Errorf("failed to issue certificate: %w", err)
		}
	}

	p.proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{p.upstreamClientCert},
			RootCAs:      p.upstreamRootCAs,
			MinVersion:   tls.VersionTLS12,
		},
	}

	return nil
}

func resolveAPIProxyHost(projectID uuid.UUID, apiHost string) string {
	host := resolveBaseAPIProxyHost(apiHost)
	if projectID == uuid.Nil {
		return host
	}
	projectPrefix := projectID.String() + "."
	if strings.HasPrefix(host, projectPrefix) {
		return host
	}
	if strings.HasPrefix(host, "apiz.") || strings.HasPrefix(host, "apiz-") {
		return projectPrefix + host
	}
	return host
}

func resolveBaseAPIProxyHost(apiHost string) string {
	switch {
	case apiHost == "", apiHost == defaultAPIHost:
		return defaultAPIProxyHost
	case strings.HasPrefix(apiHost, "apiz."), strings.HasPrefix(apiHost, "apiz-"):
		return apiHost
	case strings.HasPrefix(apiHost, "api."):
		return "apiz." + strings.TrimPrefix(apiHost, "api.")
	case strings.HasPrefix(apiHost, "api-"):
		return "apiz-" + strings.TrimPrefix(apiHost, "api-")
	default:
		return apiHost
	}
}

func newCloudReverseProxy(remote *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(remote)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = remote.Host
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		log.Printf("api service proxy upstream error for %s %s: %v", req.Method, req.URL.String(), err)
		w.WriteHeader(http.StatusBadGateway)
	}
	return proxy
}

func buildUpstreamRootCAs(caPEM []byte) (*x509.CertPool, error) {
	roots, err := systemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if len(caPEM) == 0 {
		return roots, nil
	}
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to append CA certificate to cert pool")
	}
	return roots, nil
}

// loadUpstreamCertificate loads the upstream client certificate from the secret.
func (p *APIServiceProxy) loadUpstreamCertificate(ctx context.Context) (bool, error) {
	log.Printf("loading certificate for project %s", p.opts.ProjectID)

	secret, err := p.kC.CoreV1().Secrets(p.opts.Namespace).Get(ctx, apizCertSecretName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	cert, err := tls.X509KeyPair(secret.Data[tlsSecretCert], secret.Data[tlsSecretKey])
	if err != nil {
		return false, err
	}
	p.upstreamClientCert = cert

	p.upstreamRootCAs, err = buildUpstreamRootCAs(secret.Data[tlsSecretCA])
	if err != nil {
		return false, err
	}

	return true, nil
}

func (p *APIServiceProxy) saveCertificate(ctx context.Context, certPem, keyPem, caPem []byte) error {
	log.Printf("saving certificate for project %s", p.opts.ProjectID)

	certSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: apizCertSecretName,
		},
		Data: map[string][]byte{
			tlsSecretCert: certPem,
			tlsSecretKey:  keyPem,
			tlsSecretCA:   caPem,
		},
		Type: corev1.SecretTypeTLS,
	}

	if _, err := p.kC.CoreV1().Secrets(p.opts.Namespace).Create(ctx, certSecret, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
		existing, getErr := p.kC.CoreV1().Secrets(p.opts.Namespace).Get(ctx, apizCertSecretName, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		certSecret.ResourceVersion = existing.ResourceVersion
		if _, err := p.kC.CoreV1().Secrets(p.opts.Namespace).Update(ctx, certSecret, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func (p *APIServiceProxy) issueCertificate(ctx context.Context) error {
	log.Printf("issuing certificate for project %s", p.opts.ProjectID)

	host := p.opts.APIHost
	if host == "" {
		host = defaultAPIHost
	}
	addr := fmt.Sprintf("https://%s/v1/terra/serviceaccount/certificate", host)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, nil)
	if err != nil {
		return err
	}
	req.Header.Set(ApoxyAPIKeyHeaderKey, p.opts.Token)
	req.Header.Set(ApoxyProjectIdHeaderKey, p.opts.ProjectID.String())
	req.Header.Set(ApoxyServiceUserKey, kubeControllerUserPrefix+p.opts.ClusterName)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to issue certificate (status code %d): %s", resp.StatusCode, string(body))
	}

	var certResp IssueClientCertResponse
	if err := json.Unmarshal(body, &certResp); err != nil {
		return err
	}

	if err := p.saveCertificate(ctx, []byte(certResp.Certificate), []byte(certResp.PrivateKey), []byte(certResp.CA)); err != nil {
		return err
	}

	_, err = p.loadUpstreamCertificate(ctx)
	return err
}

func (p *APIServiceProxy) ensureServingCertificate(ctx context.Context) error {
	ok, err := p.loadServingCertificate(ctx)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	cert, certPEM, keyPEM, caPEM, err := generateServingCertificate(p.opts.ServiceName, p.opts.Namespace)
	if err != nil {
		return err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: apiServiceServingSecretName,
		},
		Data: map[string][]byte{
			tlsSecretCert: certPEM,
			tlsSecretKey:  keyPEM,
			tlsSecretCA:   caPEM,
		},
		Type: corev1.SecretTypeTLS,
	}
	if _, err := p.kC.CoreV1().Secrets(p.opts.Namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
		ok, loadErr := p.loadServingCertificate(ctx)
		if loadErr != nil {
			return loadErr
		}
		if !ok {
			return fmt.Errorf("serving certificate secret %q already exists but could not be loaded", apiServiceServingSecretName)
		}
		return nil
	}

	p.servingCert = cert
	p.caBundle = caPEM
	return nil
}

func (p *APIServiceProxy) loadServingCertificate(ctx context.Context) (bool, error) {
	secret, err := p.kC.CoreV1().Secrets(p.opts.Namespace).Get(ctx, apiServiceServingSecretName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	cert, err := tls.X509KeyPair(secret.Data[tlsSecretCert], secret.Data[tlsSecretKey])
	if err != nil {
		return false, err
	}
	p.servingCert = cert
	p.caBundle = append([]byte(nil), secret.Data[tlsSecretCA]...)
	return true, nil
}
