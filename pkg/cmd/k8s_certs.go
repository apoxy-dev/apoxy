package cmd

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/cert"
	"github.com/apoxy-dev/apoxy/pkg/cmd/utils"
	"github.com/apoxy-dev/apoxy/pkg/kube-controller/apiserviceproxy"
)

const (
	certSecretName       = "apiz-cert"
	kubeControllerName   = "kube-controller"
	certRotatedAnnoKey   = "apoxy.dev/cert-rotated-at"
	certFingerprintAnno  = "apoxy.dev/cert-fingerprint"
	kubeControllerPrefix = "kube-controller-"
)

// serviceCertView mirrors proto/terra/v1.ServiceCert for JSON decoding. We
// don't depend on the generated proto package — keeps the CLI's module
// graph independent.
type serviceCertView struct {
	Fingerprint string  `json:"fingerprint"`
	ProjectID   string  `json:"projectId"`
	IssuedAt    string  `json:"issuedAt,omitempty"`
	ExpiresAt   string  `json:"expiresAt,omitempty"`
	RevokedAt   *string `json:"revokedAt,omitempty"`
}

type listServiceCertsResponse struct {
	Certs []serviceCertView `json:"certs"`
}

type issueClientCertResponse struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
	CA          string `json:"ca"`
}

// loadUserJWT resolves the user-mode bearer token used to authenticate to
// RevokeServiceCert (the one endpoint that rejects API-key auth).
// Precedence: --user-jwt flag → APOXY_USER_JWT env → ~/.config/apoxy/user-jwt.
// Returns empty string when no source has a value so callers can render
// their own "where to obtain a JWT" hint.
func loadUserJWT(flagValue string) (string, error) {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(os.Getenv("APOXY_USER_JWT")); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", nil
	}
	path := filepath.Join(home, ".config", "apoxy", "user-jwt")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// fingerprintFromCertPEM decodes a PEM cert block and returns the SHA1
// fingerprint plus the cert's NotAfter. Parsing the X.509 is best-effort:
// if it fails (e.g. cosmos-issued certs that don't parse as standard ASN.1
// somewhere) we still return the fingerprint and a zero time.
func fingerprintFromCertPEM(pemBytes []byte) (string, time.Time, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", time.Time{}, fmt.Errorf("no PEM block found in cert data")
	}
	if block.Type != "CERTIFICATE" {
		return "", time.Time{}, fmt.Errorf("expected CERTIFICATE PEM block, got %q", block.Type)
	}
	fp := cert.Fingerprint(block.Bytes)
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fp, time.Time{}, nil
	}
	return fp, parsed.NotAfter, nil
}

// readClusterName returns the cluster identifier the kube-controller was
// installed with. The onboarding manifest writes this as a namespace
// annotation; absence means the controller wasn't installed via
// `apoxy k8s install`.
func readClusterName(ctx context.Context, clientset kubernetes.Interface, namespace string) (string, error) {
	ns, err := clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("namespace %q not found — run `apoxy k8s install` first", namespace)
		}
		return "", fmt.Errorf("get namespace %s: %w", namespace, err)
	}
	v, ok := ns.Annotations[clusterNameAnnotation]
	if !ok || v == "" {
		return "", fmt.Errorf("namespace %s is missing annotation %q; either re-run `apoxy k8s install --cluster-name <name>` "+
			"or set it manually: kubectl annotate ns %s %s=<name>",
			namespace, clusterNameAnnotation, namespace, clusterNameAnnotation)
	}
	return v, nil
}

// readCertSecret fetches the in-cluster cert Secret. Returns the parsed
// fingerprint, expiry, and the full Secret (kept so callers can do an
// optimistic-concurrency Update with the original ResourceVersion).
func readCertSecret(ctx context.Context, clientset kubernetes.Interface, namespace string) (*corev1.Secret, string, time.Time, error) {
	sec, err := clientset.CoreV1().Secrets(namespace).Get(ctx, certSecretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, "", time.Time{}, fmt.Errorf("Secret %s/%s not found — the controller hasn't issued a cert yet "+
				"(check `kubectl get pods -n %s` and rerun `apoxy k8s install` if needed)",
				namespace, certSecretName, namespace)
		}
		return nil, "", time.Time{}, fmt.Errorf("get secret %s/%s: %w", namespace, certSecretName, err)
	}
	tlsCrt, ok := sec.Data["tls.crt"]
	if !ok || len(tlsCrt) == 0 {
		return sec, "", time.Time{}, fmt.Errorf("Secret %s/%s has no tls.crt — was the controller initialized correctly?",
			namespace, certSecretName)
	}
	fp, expiresAt, err := fingerprintFromCertPEM(tlsCrt)
	if err != nil {
		return sec, "", time.Time{}, fmt.Errorf("parse tls.crt in %s/%s: %w", namespace, certSecretName, err)
	}
	return sec, fp, expiresAt, nil
}

// issueServiceCert posts to /v1/terra/serviceaccount/certificate for the
// given service-user and returns the new cert material.
func issueServiceCert(ctx context.Context, serviceUser string) (*issueClientCertResponse, error) {
	c, err := config.DefaultAPIClient()
	if err != nil {
		return nil, err
	}
	url := c.BaseURL + "/v1/terra/serviceaccount/certificate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(apiserviceproxy.ApoxyAPIKeyHeaderKey, c.APIKey)
	req.Header.Set(apiserviceproxy.ApoxyProjectIdHeaderKey, c.ProjectID.String())
	req.Header.Set(apiserviceproxy.ApoxyServiceUserKey, serviceUser)
	if c.BaseHost != "" {
		req.Host = c.BaseHost
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issue cert (status %d): %s", resp.StatusCode, string(body))
	}
	var out issueClientCertResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode issue cert response: %w", err)
	}
	if out.Certificate == "" || out.PrivateKey == "" || out.CA == "" {
		return nil, fmt.Errorf("issue cert response missing fields: %s", string(body))
	}
	return &out, nil
}

// getServiceCert calls GET /v1/terra/serviceaccount/certificate/{fp}.
// Returns (nil, 404, nil) when the fingerprint is absent — caller decides
// whether that's expected.
func getServiceCert(ctx context.Context, fingerprint string) (*serviceCertView, int, error) {
	c, err := config.DefaultAPIClient()
	if err != nil {
		return nil, 0, err
	}
	url := c.BaseURL + "/v1/terra/serviceaccount/certificate/" + fingerprint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set(apiserviceproxy.ApoxyAPIKeyHeaderKey, c.APIKey)
	req.Header.Set(apiserviceproxy.ApoxyProjectIdHeaderKey, c.ProjectID.String())
	if c.BaseHost != "" {
		req.Host = c.BaseHost
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("get cert: %s", string(body))
	}
	var view serviceCertView
	if err := json.Unmarshal(body, &view); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode get cert: %w", err)
	}
	return &view, resp.StatusCode, nil
}

// listServiceCerts calls GET /v1/terra/serviceaccount/certificate.
func listServiceCerts(ctx context.Context, includeRevoked bool) (*listServiceCertsResponse, error) {
	c, err := config.DefaultAPIClient()
	if err != nil {
		return nil, err
	}
	url := c.BaseURL + "/v1/terra/serviceaccount/certificate"
	if includeRevoked {
		url += "?includeRevoked=true"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(apiserviceproxy.ApoxyAPIKeyHeaderKey, c.APIKey)
	req.Header.Set(apiserviceproxy.ApoxyProjectIdHeaderKey, c.ProjectID.String())
	if c.BaseHost != "" {
		req.Host = c.BaseHost
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list certs (status %d): %s", resp.StatusCode, string(body))
	}
	var out listServiceCertsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode list certs: %w", err)
	}
	return &out, nil
}

// revokeServiceCert sends DELETE /v1/terra/serviceaccount/certificate/{fp}
// using a user JWT. Cosmos requires user auth here by design — an
// exfiltrated API key must not be able to revoke the cert it lives next to.
func revokeServiceCert(ctx context.Context, fingerprint, userJWT string) error {
	c, err := config.DefaultAPIClient()
	if err != nil {
		return err
	}
	url := c.BaseURL + "/v1/terra/serviceaccount/certificate/" + fingerprint
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+userJWT)
	req.Header.Set(apiserviceproxy.ApoxyProjectIdHeaderKey, c.ProjectID.String())
	if c.BaseHost != "" {
		req.Host = c.BaseHost
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("revoke rejected by cosmos (status %d). The user JWT is required for revoke; obtain one "+
			"by logging in via the dashboard and exporting APOXY_USER_JWT (or pass --user-jwt). Response: %s",
			resp.StatusCode, string(body))
	case http.StatusNotFound:
		return fmt.Errorf("certificate %s not found for project (already revoked, or wrong project)", fingerprint)
	default:
		return fmt.Errorf("revoke cert (status %d): %s", resp.StatusCode, string(body))
	}
}

func runCertsList(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true
	ctx := cmd.Context()

	kubeconfigPath, _ := cmd.Flags().GetString("kubeconfig")
	kubeconfigPath = resolveKubeconfigPath(kubeconfigPath)
	kubeContext, _ := cmd.Flags().GetString("context")
	namespace, _ := cmd.Flags().GetString("namespace")
	all, _ := cmd.Flags().GetBool("all")

	kc, _, err := loadKubeClientConfig(kubeconfigPath, kubeContext)
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(kc)
	if err != nil {
		return err
	}

	_, localFP, expiresLocal, err := readCertSecret(ctx, clientset, namespace)
	if err != nil {
		return err
	}

	server, code, err := getServiceCert(ctx, localFP)
	if err != nil && code == 0 {
		return err
	}

	fmt.Printf("Cluster Secret %s/%s:\n", namespace, certSecretName)
	fmt.Printf("  Fingerprint: %s\n", localFP)
	if !expiresLocal.IsZero() {
		fmt.Printf("  Expires:     %s (%s)\n", expiresLocal.Format(time.RFC3339), humanUntil(expiresLocal))
	}
	switch {
	case code == http.StatusNotFound:
		fmt.Println("  Status:      not found on cosmos (cert may belong to another project)")
	case server == nil:
		fmt.Printf("  Status:      lookup failed (code %d)\n", code)
	case server.RevokedAt != nil:
		fmt.Printf("  Status:      REVOKED at %s\n", *server.RevokedAt)
	default:
		fmt.Println("  Status:      active")
	}

	if !all {
		return nil
	}
	list, err := listServiceCerts(ctx, true)
	if err != nil {
		return fmt.Errorf("list certs: %w", err)
	}
	fmt.Printf("\nProject certs (%d):\n", len(list.Certs))
	for _, c := range list.Certs {
		marker := " "
		if c.Fingerprint == localFP {
			marker = "*"
		}
		status := "active"
		if c.RevokedAt != nil {
			status = "revoked " + *c.RevokedAt
		}
		fmt.Printf("  %s %s  exp=%s  %s\n", marker, c.Fingerprint, c.ExpiresAt, status)
	}
	fmt.Println("\n  (* = in-cluster Secret)")
	return nil
}

func runCertsRotate(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true
	ctx := cmd.Context()

	kubeconfigPath, _ := cmd.Flags().GetString("kubeconfig")
	kubeconfigPath = resolveKubeconfigPath(kubeconfigPath)
	kubeContext, _ := cmd.Flags().GetString("context")
	namespace, _ := cmd.Flags().GetString("namespace")
	yes, _ := cmd.Flags().GetBool("yes")
	revoke, _ := cmd.Flags().GetBool("revoke")
	userJWTFlag, _ := cmd.Flags().GetString("user-jwt")
	waitTimeout, _ := cmd.Flags().GetDuration("wait-timeout")
	allowDisruption, _ := cmd.Flags().GetBool("allow-disruption")
	noRestart, _ := cmd.Flags().GetBool("no-restart")
	reloadWait, _ := cmd.Flags().GetDuration("reload-wait")

	kc, kubeCtxName, err := loadKubeClientConfig(kubeconfigPath, kubeContext)
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(kc)
	if err != nil {
		return err
	}

	clusterName, err := readClusterName(ctx, clientset, namespace)
	if err != nil {
		return err
	}

	oldSec, oldFP, oldExp, err := readCertSecret(ctx, clientset, namespace)
	if err != nil {
		return err
	}

	dep, err := clientset.AppsV1().Deployments(namespace).Get(ctx, kubeControllerName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("Deployment %s/%s not found — run `apoxy k8s install` first", namespace, kubeControllerName)
		}
		return fmt.Errorf("get deployment %s/%s: %w", namespace, kubeControllerName, err)
	}
	// --no-restart skips the rolling restart so the pod hot-reloads the
	// cert via fsnotify on the projected Secret. Skip the strategy check
	// (no pod swap means single-replica + Recreate constraints don't
	// apply). Override --allow-disruption silently — the constraints are
	// only meaningful for the restart path.
	if !noRestart {
		if err := assertSafeStrategy(dep, allowDisruption); err != nil {
			return err
		}
	}

	serviceUser := kubeControllerPrefix + clusterName

	fmt.Println("About to rotate the service-account certificate for kube-controller:")
	fmt.Printf("  Context:       %s\n", kubeCtxName)
	fmt.Printf("  Namespace:     %s\n", namespace)
	fmt.Printf("  Cluster:       %s\n", clusterName)
	fmt.Printf("  Service user:  %s\n", serviceUser)
	fmt.Printf("  Current fp:    %s", oldFP)
	if !oldExp.IsZero() {
		fmt.Printf("  (expires %s)", oldExp.Format(time.RFC3339))
	}
	fmt.Println()
	fmt.Println()
	fmt.Println("Plan:")
	fmt.Println("  1. Issue a new cert from cosmos (old cert remains valid).")
	fmt.Printf("  2. Update Secret %s/%s with new cert material.\n", namespace, certSecretName)
	if noRestart {
		fmt.Printf("  3. Wait for kube-controller to hot-reload the cert via fsnotify (kubelet projection ~60s).\n")
	} else {
		fmt.Printf("  3. Roll Deployment %s/%s (rolling update; new pod up before old terminates).\n", namespace, kubeControllerName)
	}
	if revoke {
		fmt.Println("  4. Revoke the old cert on cosmos (requires user JWT).")
	} else {
		fmt.Println("  4. Print the old fingerprint; revoke is left to a follow-up command.")
	}
	fmt.Println()

	if !yes {
		if !utils.IsInteractive() {
			return fmt.Errorf("non-interactive mode without --yes; pass --yes to proceed")
		}
		if !confirm("Proceed?") {
			return fmt.Errorf("aborted")
		}
	}

	fmt.Println("\n[1/4] Issuing new cert...")
	issued, err := issueServiceCert(ctx, serviceUser)
	if err != nil {
		return fmt.Errorf("issue new cert: %w", err)
	}
	newFP, newExp, err := fingerprintFromCertPEM([]byte(issued.Certificate))
	if err != nil {
		return fmt.Errorf("parse new cert: %w", err)
	}
	fmt.Printf("       new fingerprint = %s\n", newFP)

	fmt.Printf("\n[2/4] Writing Secret %s/%s (ResourceVersion=%s)...\n",
		namespace, certSecretName, oldSec.ResourceVersion)
	newSec := oldSec.DeepCopy()
	newSec.Data = map[string][]byte{
		"tls.crt": []byte(issued.Certificate),
		"tls.key": []byte(issued.PrivateKey),
		"ca.crt":  []byte(issued.CA),
	}
	if _, err := clientset.CoreV1().Secrets(namespace).Update(ctx, newSec, metav1.UpdateOptions{}); err != nil {
		if apierrors.IsConflict(err) {
			return fmt.Errorf("Secret %s/%s changed mid-rotation (another rotate in flight?); abort, then retry: %w",
				namespace, certSecretName, err)
		}
		return fmt.Errorf("update secret %s/%s: %w", namespace, certSecretName, err)
	}

	if noRestart {
		fmt.Printf("\n[3/4] Waiting for kube-controller to hot-reload (up to %s)...\n", reloadWait)
		if reloadWait > 0 {
			if err := waitForCertHotReload(ctx, clientset, namespace, newExp, reloadWait); err != nil {
				fmt.Printf("       %v\n", err)
				fmt.Println("       The Secret has the new cert; the running pod will pick it up on the next kubelet sync.")
				fmt.Println("       Verify with: apoxy k8s certs list")
			}
		}
	} else {
		fmt.Printf("\n[3/4] Rolling Deployment %s/%s...\n", namespace, kubeControllerName)
		if err := triggerDeploymentRestart(ctx, clientset, namespace, kubeControllerName, newFP); err != nil {
			return fmt.Errorf("trigger restart: %w", err)
		}
		// waitTimeout=0 means "don't wait" — useful in dev where the pod
		// readiness signal aggregates the tunnel component, which can't reach
		// the in-cluster tunnelproxy without extra wiring.
		if waitTimeout > 0 {
			targets := []rolloutTarget{{kind: "Deployment", namespace: namespace, name: kubeControllerName}}
			if err := waitForCertRollout(ctx, clientset, targets, waitTimeout); err != nil {
				return fmt.Errorf("wait for rollout: %w", err)
			}
		}
	}

	fmt.Println("\n[4/4] Cert rotation complete.")
	fmt.Printf("       new = %s\n       old = %s\n", newFP, oldFP)

	if revoke {
		jwt, err := loadUserJWT(userJWTFlag)
		if err != nil {
			return err
		}
		if jwt == "" {
			fmt.Println("\nNo user JWT available — skipping revoke.")
			printRevokeFollowup(oldFP)
			return nil
		}
		fmt.Println("\nRevoking old cert on cosmos...")
		if err := revokeServiceCert(ctx, oldFP, jwt); err != nil {
			return err
		}
		fmt.Println("Revoked. ext_authz CRL propagates within ~30s.")
		return nil
	}

	printRevokeFollowup(oldFP)
	return nil
}

func printRevokeFollowup(oldFP string) {
	fmt.Println("\nOld cert is still valid on cosmos. Revoke when you've confirmed nothing else uses it:")
	fmt.Printf("  apoxy k8s certs revoke %s --user-jwt <jwt>\n", oldFP)
	fmt.Println("  (or set APOXY_USER_JWT; the JWT is the PropelAuth access token from the dashboard)")
}

func assertSafeStrategy(d *appsv1.Deployment, allowDisruption bool) error {
	if allowDisruption {
		return nil
	}
	replicas := int32(1)
	if d.Spec.Replicas != nil {
		replicas = *d.Spec.Replicas
	}
	if replicas > 1 {
		return fmt.Errorf("Deployment %s has %d replicas; rotate's zero-downtime guarantee assumes the "+
			"default single-replica controller. Pass --allow-disruption if you've verified your topology",
			d.Name, replicas)
	}
	// Strategy = "" defaults to RollingUpdate with safe rounding on 1 replica
	// (maxSurge=1, maxUnavailable=0). Explicit Recreate would drop traffic;
	// refuse without --allow-disruption.
	if d.Spec.Strategy.Type == appsv1.RecreateDeploymentStrategyType {
		return fmt.Errorf("Deployment %s uses Recreate strategy — would drop traffic. "+
			"Pass --allow-disruption to proceed", d.Name)
	}
	return nil
}

// triggerDeploymentRestart patches the pod-template annotations to force a
// rolling restart that picks up the new Secret content.
func triggerDeploymentRestart(ctx context.Context, clientset kubernetes.Interface, namespace, name, newFingerprint string) error {
	patch := fmt.Sprintf(
		`{"spec":{"template":{"metadata":{"annotations":{%q:%q,%q:%q}}}}}`,
		certRotatedAnnoKey, time.Now().UTC().Format(time.RFC3339),
		certFingerprintAnno, newFingerprint,
	)
	_, err := clientset.AppsV1().Deployments(namespace).Patch(
		ctx, name, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{},
	)
	return err
}

// waitForCertRollout dispatches to the install command's existing TUI/plain
// rollout poller. rotate has a single static target so we bypass the
// resourcePlan-based wrapper.
func waitForCertRollout(ctx context.Context, clientset kubernetes.Interface, targets []rolloutTarget, timeout time.Duration) error {
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if utils.IsInteractive() {
		return runRolloutTUI(wctx, clientset, targets)
	}
	return runRolloutPlain(wctx, clientset, targets)
}

// waitForCertHotReload polls the kube-controller's prometheus /metrics via
// the apiserver pod-proxy until the cert-expiry gauge matches the new
// cert's NotAfter. The gauge is bumped only on a successful reload, so a
// match is a positive signal that the running pod has the new cert in
// memory. We avoid port-forwarding so this works in headless CI without
// extra plumbing.
func waitForCertHotReload(ctx context.Context, clientset kubernetes.Interface, namespace string, newExpiry time.Time, timeout time.Duration) error {
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pods, err := clientset.CoreV1().Pods(namespace).List(wctx, metav1.ListOptions{
		LabelSelector: "app=" + kubeControllerName,
	})
	if err != nil {
		return fmt.Errorf("list kube-controller pods: %w", err)
	}
	if len(pods.Items) == 0 {
		return fmt.Errorf("no kube-controller pods found in namespace %s", namespace)
	}
	// Single-replica deployment, so taking the first pod is fine.
	pod := pods.Items[0]
	target := newExpiry.Unix()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		body, err := clientset.CoreV1().RESTClient().Get().
			Namespace(namespace).
			Resource("pods").
			Name(pod.Name + ":8083").
			SubResource("proxy").
			Suffix("metrics").
			DoRaw(wctx)
		if err == nil {
			if got, ok := parseExpiryMetric(body); ok && got == target {
				fmt.Printf("       hot-reload confirmed (pod %s, expiry gauge=%d).\n", pod.Name, got)
				return nil
			}
		}
		select {
		case <-wctx.Done():
			return fmt.Errorf("timed out after %s waiting for hot-reload on pod %s", timeout, pod.Name)
		case <-ticker.C:
		}
	}
}

// parseExpiryMetric pulls the apoxy_kube_controller_cert_expiry_seconds
// value out of a prometheus text-format scrape. Returns (value, true) on
// success, (0, false) on any malformed input — caller treats that as
// "keep polling."
func parseExpiryMetric(body []byte) (int64, bool) {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "apoxy_kube_controller_cert_expiry_seconds") {
			continue
		}
		// Format: "<name>[{labels}] <value>" — the gauge has no labels.
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		var v float64
		if _, err := fmt.Sscanf(parts[len(parts)-1], "%f", &v); err != nil {
			continue
		}
		return int64(v), true
	}
	return 0, false
}

func runCertsRevoke(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true
	ctx := cmd.Context()

	fp, err := cert.NormalizeFingerprint(args[0])
	if err != nil {
		return err
	}
	userJWTFlag, _ := cmd.Flags().GetString("user-jwt")
	jwt, err := loadUserJWT(userJWTFlag)
	if err != nil {
		return err
	}
	if jwt == "" {
		return fmt.Errorf("a user JWT is required: pass --user-jwt, set APOXY_USER_JWT, or write ~/.config/apoxy/user-jwt. " +
			"The JWT is the PropelAuth access token from the dashboard (API keys are intentionally rejected for this operation)")
	}
	if err := revokeServiceCert(ctx, fp, jwt); err != nil {
		return err
	}
	fmt.Printf("Revoked %s. ext_authz CRL propagates within ~30s.\n", fp)
	return nil
}

// humanUntil renders a duration as "in 12d3h" / "expired 5h ago".
func humanUntil(t time.Time) string {
	d := time.Until(t)
	abs := d
	if abs < 0 {
		abs = -abs
	}
	days := int(abs / (24 * time.Hour))
	hours := int((abs % (24 * time.Hour)) / time.Hour)
	if d < 0 {
		return fmt.Sprintf("expired %dd%dh ago", days, hours)
	}
	return fmt.Sprintf("in %dd%dh", days, hours)
}

func confirm(prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

var certsK8sCmd = &cobra.Command{
	Use:   "certs",
	Short: "Manage the service-account certificate used by the in-cluster controller",
}

var certsListK8sCmd = &cobra.Command{
	Use:   "list",
	Short: "Show the in-cluster cert and its server-side status",
	Args:  cobra.NoArgs,
	RunE:  runCertsList,
}

var certsRotateK8sCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the in-cluster cert without dropping the aggregated API",
	Long: `Rotate the service-account certificate held by the kube-controller Deployment.

The flow:
  1. Issue a new cert from cosmos (the old cert remains valid).
  2. Update Secret apoxy/apiz-cert with the new cert material.
  3. Trigger a rolling restart of Deployment apoxy/kube-controller. With 1 replica
     and the default rolling-update strategy, k8s brings the new pod up Ready
     before terminating the old one — so traffic never goes through a controller
     with no cert.
  4. Optionally revoke the old cert (requires a user JWT; cosmos refuses to
     accept API-key auth on revoke so a leaked API key can't kill its own cert).

If --revoke is not set, the old cert keeps working until natural expiry; the
follow-up `+"`"+`apoxy k8s certs revoke`+"`"+` command is printed at the end.`,
	Args: cobra.NoArgs,
	RunE: runCertsRotate,
}

var certsRevokeK8sCmd = &cobra.Command{
	Use:   "revoke <fingerprint>",
	Short: "Revoke a service-account cert by SHA1 fingerprint",
	Args:  cobra.ExactArgs(1),
	RunE:  runCertsRevoke,
}

func init() {
	for _, c := range []*cobra.Command{certsListK8sCmd, certsRotateK8sCmd} {
		c.Flags().String("kubeconfig", "", "Path to the kubeconfig file")
		c.Flags().String("context", "", "Kubernetes context to use")
		c.Flags().String("namespace", "apoxy", "Namespace where the controller is installed")
	}
	certsListK8sCmd.Flags().Bool("all", false, "Also list every cert cosmos has for this project (including revoked)")

	certsRotateK8sCmd.Flags().BoolP("yes", "y", false, "Skip the confirmation prompt")
	certsRotateK8sCmd.Flags().Bool("revoke", false, "Revoke the old cert after the rollout completes (needs --user-jwt or APOXY_USER_JWT)")
	certsRotateK8sCmd.Flags().String("user-jwt", "", "User JWT used for revoke; defaults to APOXY_USER_JWT then ~/.config/apoxy/user-jwt")
	certsRotateK8sCmd.Flags().Duration("wait-timeout", 5*time.Minute, "Maximum wait for the new pod to become Ready (kube-controller startup probe is generous)")
	certsRotateK8sCmd.Flags().Bool("allow-disruption", false, "Allow rotate to proceed against multi-replica or Recreate-strategy Deployments")
	certsRotateK8sCmd.Flags().Bool("no-restart", false, "Skip the pod-template restart; rely on the controller's fsnotify hot-reload (requires a controller built with hot-reload support)")
	certsRotateK8sCmd.Flags().Duration("reload-wait", 3*time.Minute, "Maximum wait for the running pod to pick up the new cert when --no-restart is set")

	certsRevokeK8sCmd.Flags().String("user-jwt", "", "User JWT used for revoke; defaults to APOXY_USER_JWT then ~/.config/apoxy/user-jwt")

	certsK8sCmd.AddCommand(certsListK8sCmd, certsRotateK8sCmd, certsRevokeK8sCmd)
	k8sCmd.AddCommand(certsK8sCmd)
}
