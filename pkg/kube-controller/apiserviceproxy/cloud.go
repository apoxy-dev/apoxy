package apiserviceproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Cosmos APIs.
	apiHost = "api.apoxy.dev"
	// APIServer APIs.
	apizHost                 = "apiz.apoxy.dev"
	kubeControllerUserPrefix = "kube-controller-"

	apizCertSecretName = "apiz-cert"
	tlsSecretCert      = "tls.crt"
	tlsSecretKey       = "tls.key"
	tlsSecretCA        = "ca.crt"

	// Apoxy API headers.
	ApoxyAPIKeyHeaderKey    = "x-apoxy-api-key"
	ApoxyProjectIdHeaderKey = "x-apoxy-project-id"
	ApoxyServiceUserKey     = "x-apoxy-service-user"
)

// IssueClientCertResponse is the response from the certificate issuance endpoint.
type IssueClientCertResponse struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	CA          string `json:"ca"`
}

func (p *APIServiceProxy) configureCloudProxy(ctx context.Context) error {
	log.Printf("configuring cloud proxy for project %s", p.opts.ProjectID)

	remote, err := url.Parse(fmt.Sprintf("https://%s", apizHost))
	if err != nil {
		return fmt.Errorf("failed to parse remote URL: %w", err)
	}
	p.proxy = httputil.NewSingleHostReverseProxy(remote)

	ok, err := p.loadCertificate(ctx)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}
	if !ok {
		if err := p.issueCertificate(ctx); err != nil {
			return fmt.Errorf("failed to issue certificate: %w", err)
		}
	}

	p.proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{p.cert},
			RootCAs:      p.certPool,
		},
	}

	return nil
}

// loadCertificate loads the certificate from the secret.
func (p *APIServiceProxy) loadCertificate(ctx context.Context) (bool, error) {
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
	p.cert = cert

	p.certPool = x509.NewCertPool()
	if !p.certPool.AppendCertsFromPEM(secret.Data[tlsSecretCA]) {
		return false, fmt.Errorf("failed to append CA certificate to cert pool")
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
		// Update the secret.
		if _, err := p.kC.CoreV1().Secrets(p.opts.Namespace).Update(ctx, certSecret, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func (p *APIServiceProxy) issueCertificate(ctx context.Context) error {
	log.Printf("issuing certificate for project %s", p.opts.ProjectID)

	addr := fmt.Sprintf("https://%s/v1/terra/serviceaccount/certificate", apiHost)
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

	body, err := ioutil.ReadAll(resp.Body)
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

	_, err = p.loadCertificate(ctx)
	return err
}
