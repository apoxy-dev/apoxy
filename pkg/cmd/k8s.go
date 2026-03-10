package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	runtimejson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	sigyaml "sigs.k8s.io/yaml"

	"github.com/apoxy-dev/apoxy/config"
)

const clusterNameAnnotation = "apoxy.dev/cluster-name"

var (
	decoder = scheme.Codecs.UniversalDeserializer()
	encoder = runtimejson.NewYAMLSerializer(runtimejson.DefaultMetaFactory, scheme.Scheme, scheme.Scheme)
)

func getYAML(clusterName, mirror string) ([]byte, error) {
	c, err := config.DefaultAPIClient()
	if err != nil {
		return nil, err
	}

	path := "/v1/onboarding/k8s.yaml"
	params := url.Values{}
	if clusterName != "" {
		params.Set("cluster_name", clusterName)
	}
	if mirror != "" {
		params.Set("mirror", mirror)
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	resp, err := c.SendRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func resolveKubeconfigPath(explicitPath string) string {
	if explicitPath != "" {
		return explicitPath
	}
	if kubeconfig, ok := os.LookupEnv("KUBECONFIG"); ok {
		return kubeconfig
	}
	return clientcmd.RecommendedHomeFile
}

func loadKubeClientConfig(kubeconfigPath, kubeContext string) (*rest.Config, string, error) {
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	overrides := &clientcmd.ConfigOverrides{}
	if kubeContext != "" {
		overrides.CurrentContext = kubeContext
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	rawConfig, err := clientConfig.RawConfig()
	if err != nil {
		return nil, "", fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	kc, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("failed to build Kubernetes config: %w", err)
	}

	selectedContext := rawConfig.CurrentContext
	if kubeContext != "" {
		selectedContext = kubeContext
	}

	return kc, selectedContext, nil
}

// --- Plan types ---

type resourceAction int

const (
	actionCreate resourceAction = iota
	actionUpdate
	actionUnchanged
)

type resourcePlan struct {
	obj     *unstructured.Unstructured
	mapping *meta.RESTMapping
	action  resourceAction
	diff    string
	gvkStr  string
}

type applyResult struct {
	index int
	err   error
}

// --- Styles ---

var (
	styleCreate    = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	styleUpdate    = lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	styleUnchanged = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	styleDiffAdd   = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	styleDiffRem   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleHeader    = lipgloss.NewStyle().Bold(true)
	styleError     = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
)

// --- Diff helpers ---

func stripServerFields(obj map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		if k == "status" {
			continue
		}
		out[k] = v
	}
	if md, ok := out["metadata"].(map[string]interface{}); ok {
		cleaned := make(map[string]interface{}, len(md))
		for k, v := range md {
			switch k {
			case "resourceVersion", "uid", "creationTimestamp", "generation", "managedFields":
				continue
			default:
				cleaned[k] = v
			}
		}
		out["metadata"] = cleaned
	}
	return out
}

func computeDiff(existing, desired *unstructured.Unstructured) string {
	existingYAML, err := sigyaml.Marshal(stripServerFields(existing.Object))
	if err != nil {
		return ""
	}
	desiredYAML, err := sigyaml.Marshal(stripServerFields(desired.Object))
	if err != nil {
		return ""
	}
	if bytes.Equal(existingYAML, desiredYAML) {
		return ""
	}
	a := strings.Split(strings.TrimRight(string(existingYAML), "\n"), "\n")
	b := strings.Split(strings.TrimRight(string(desiredYAML), "\n"), "\n")
	return lineDiff(a, b)
}

// lineDiff produces a unified-diff-style output treating each line as an atomic unit.
// It uses LCS to align lines and shows 3 lines of context around changes.
func lineDiff(a, b []string) string {
	m, n := len(a), len(b)

	// Build LCS length table.
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}

	// Backtrack to produce diff lines.
	type diffLine struct {
		prefix string // "  ", "- ", "+ "
		text   string
	}
	var lines []diffLine
	i, j := m, n
	for i > 0 || j > 0 {
		if i > 0 && j > 0 && a[i-1] == b[j-1] {
			lines = append(lines, diffLine{"  ", a[i-1]})
			i--
			j--
		} else if j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]) {
			lines = append(lines, diffLine{"+ ", b[j-1]})
			j--
		} else {
			lines = append(lines, diffLine{"- ", a[i-1]})
			i--
		}
	}
	for l, r := 0, len(lines)-1; l < r; l, r = l+1, r-1 {
		lines[l], lines[r] = lines[r], lines[l]
	}

	// Show 3 lines of context around each change, collapse the rest.
	const ctx = 3
	show := make([]bool, len(lines))
	for k, l := range lines {
		if l.prefix != "  " {
			lo := k - ctx
			if lo < 0 {
				lo = 0
			}
			hi := k + ctx
			if hi >= len(lines) {
				hi = len(lines) - 1
			}
			for c := lo; c <= hi; c++ {
				show[c] = true
			}
		}
	}

	var out strings.Builder
	lastShown := -1
	for k, l := range lines {
		if !show[k] {
			continue
		}
		if lastShown >= 0 && k > lastShown+1 {
			out.WriteString("  ...\n")
		}
		out.WriteString(l.prefix + l.text + "\n")
		lastShown = k
	}
	return out.String()
}

func colorizedDiff(diff string) string {
	var b strings.Builder
	for _, line := range strings.Split(diff, "\n") {
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "- "):
			b.WriteString("    " + styleDiffRem.Render(line) + "\n")
		case strings.HasPrefix(line, "+ "):
			b.WriteString("    " + styleDiffAdd.Render(line) + "\n")
		default:
			b.WriteString("    " + line + "\n")
		}
	}
	return b.String()
}

// --- Plan building ---

func buildPlan(ctx context.Context, dynClient dynamic.Interface, mapper meta.RESTMapper, yamlz []byte, ns string, force bool) ([]resourcePlan, error) {
	var plans []resourcePlan
	for _, y := range strings.Split(string(yamlz), "---") {
		if strings.TrimSpace(y) == "" {
			continue
		}

		obj := &unstructured.Unstructured{}
		_, gvk, err := decoder.Decode([]byte(y), nil, obj)
		if err != nil {
			return nil, fmt.Errorf("failed to decode YAML: %w", err)
		}

		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to get REST mapping: %w", err)
		}

		if ns != "" && gvk.Group == "" && gvk.Kind == "Namespace" {
			obj.SetName(ns)
		}

		var resource dynamic.ResourceInterface
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			if ns != "" {
				obj.SetNamespace(ns)
			}
			resource = dynClient.Resource(mapping.Resource).Namespace(obj.GetNamespace())
		} else {
			resource = dynClient.Resource(mapping.Resource)
		}

		gvkStr := obj.GroupVersionKind().String()
		if gvkStr[0] == '/' {
			gvkStr = "core" + gvkStr
		}

		existing, err := resource.Get(ctx, obj.GetName(), metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				plans = append(plans, resourcePlan{
					obj:     obj,
					mapping: mapping,
					action:  actionCreate,
					gvkStr:  gvkStr,
				})
				continue
			}
			return nil, fmt.Errorf("failed to get %s (%s): %w", obj.GetName(), gvkStr, err)
		}

		// Dry-run SSA apply to get the object with all server defaults applied,
		// then diff that against what's currently live.
		jsonData, err := json.Marshal(obj)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal %s (%s): %w", obj.GetName(), gvkStr, err)
		}
		f := force
		applied, err := resource.Patch(ctx, obj.GetName(), types.ApplyPatchType, jsonData, metav1.PatchOptions{
			FieldManager: "apoxy-cli",
			Force:        &f,
			DryRun:       []string{metav1.DryRunAll},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to dry-run apply %s (%s): %w", obj.GetName(), gvkStr, err)
		}

		diff := computeDiff(existing, applied)
		action := actionUpdate
		if diff == "" {
			action = actionUnchanged
		}
		plans = append(plans, resourcePlan{
			obj:     obj,
			mapping: mapping,
			action:  action,
			diff:    diff,
			gvkStr:  gvkStr,
		})
	}
	return plans, nil
}

// --- Plan rendering ---

func renderPlan(plans []resourcePlan) string {
	var b strings.Builder
	b.WriteString(styleHeader.Render("Resource Plan:"))
	b.WriteString("\n\n")

	for _, p := range plans {
		var tag string
		switch p.action {
		case actionCreate:
			tag = styleCreate.Render("+ create")
		case actionUpdate:
			tag = styleUpdate.Render("~ update")
		case actionUnchanged:
			tag = styleUnchanged.Render("  unchanged")
		}
		b.WriteString(fmt.Sprintf("  %s  %s (%s)\n", tag, p.obj.GetName(), p.gvkStr))
	}

	hasDiffs := false
	for _, p := range plans {
		if p.action == actionUpdate && p.diff != "" {
			if !hasDiffs {
				b.WriteString("\n")
				b.WriteString(styleHeader.Render("Changes:"))
				b.WriteString("\n")
				hasDiffs = true
			}
			b.WriteString(fmt.Sprintf("\n  %s (%s):\n", p.obj.GetName(), p.gvkStr))
			b.WriteString(colorizedDiff(p.diff))
		}
	}
	return b.String()
}

func printPlanPlain(plans []resourcePlan) {
	fmt.Println("Resource Plan:")
	fmt.Println()
	for _, p := range plans {
		var tag string
		switch p.action {
		case actionCreate:
			tag = "+ create"
		case actionUpdate:
			tag = "~ update"
		case actionUnchanged:
			tag = "  unchanged"
		}
		fmt.Printf("  %s  %s (%s)\n", tag, p.obj.GetName(), p.gvkStr)
	}
	for _, p := range plans {
		if p.action == actionUpdate && p.diff != "" {
			fmt.Printf("\n  %s (%s):\n", p.obj.GetName(), p.gvkStr)
			for _, line := range strings.Split(p.diff, "\n") {
				if line != "" {
					fmt.Printf("    %s\n", line)
				}
			}
		}
	}
}

// --- Confirmation (bubbletea inline y/N) ---

type confirmModel struct {
	kubeContext string
	confirmed   bool
	done        bool
}

func (m confirmModel) Init() tea.Cmd { return nil }

func (m confirmModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch msg.String() {
		case "y", "Y":
			m.confirmed = true
			m.done = true
			return m, tea.Quit
		case "n", "N", "enter", "q", "ctrl+c", "esc":
			m.confirmed = false
			m.done = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m confirmModel) View() string {
	prompt := fmt.Sprintf("Apply changes? [y/N]: ")
	ctx := fmt.Sprintf("  Context: %s\n", m.kubeContext)
	if m.done {
		if m.confirmed {
			return prompt + "y\n" + ctx
		}
		return prompt + "n\n" + ctx
	}
	return prompt + "\n" + ctx
}

func runConfirmation(kubeContext string) (bool, error) {
	p := tea.NewProgram(confirmModel{kubeContext: kubeContext})
	result, err := p.Run()
	if err != nil {
		return false, err
	}
	return result.(confirmModel).confirmed, nil
}

// --- Apply model (bubbletea with spinner per resource) ---

type applyResultMsg applyResult
type applyDoneMsg struct{}

func waitForApplyResult(ch <-chan applyResult) tea.Cmd {
	return func() tea.Msg {
		r, ok := <-ch
		if !ok {
			return applyDoneMsg{}
		}
		return applyResultMsg(r)
	}
}

type applyModel struct {
	plans   []resourcePlan
	done    []bool
	errors  []error
	spinner spinner.Model
	ch      <-chan applyResult
	allDone bool
}

func newApplyModel(plans []resourcePlan, ch <-chan applyResult) applyModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	return applyModel{
		plans:   plans,
		done:    make([]bool, len(plans)),
		errors:  make([]error, len(plans)),
		spinner: s,
		ch:      ch,
	}
}

func (m applyModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, waitForApplyResult(m.ch))
}

func (m applyModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case applyResultMsg:
		m.done[msg.index] = true
		m.errors[msg.index] = msg.err
		return m, waitForApplyResult(m.ch)
	case applyDoneMsg:
		m.allDone = true
		return m, tea.Quit
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m applyModel) View() string {
	var b strings.Builder
	b.WriteString("\n")
	foundInProgress := false
	for i, p := range m.plans {
		if p.action == actionUnchanged {
			b.WriteString(fmt.Sprintf("  %s %s (%s) unchanged\n",
				styleUnchanged.Render("-"), p.obj.GetName(), p.gvkStr))
			continue
		}
		if m.done[i] {
			if m.errors[i] != nil {
				b.WriteString(fmt.Sprintf("  %s %s (%s): %v\n",
					styleError.Render("✗"), p.obj.GetName(), p.gvkStr, m.errors[i]))
			} else {
				b.WriteString(fmt.Sprintf("  %s %s (%s)\n",
					styleCreate.Render("✓"), p.obj.GetName(), p.gvkStr))
			}
		} else if !foundInProgress && !m.allDone {
			foundInProgress = true
			b.WriteString(fmt.Sprintf("  %s %s (%s)\n",
				m.spinner.View(), p.obj.GetName(), p.gvkStr))
		} else {
			b.WriteString(fmt.Sprintf("    %s (%s)\n", p.obj.GetName(), p.gvkStr))
		}
	}
	if m.allDone {
		created, updated, failed := summarizePlans(m.plans, m.errors)
		b.WriteString(fmt.Sprintf("\nDone: %d created, %d updated, %d failed.\n", created, updated, failed))
	}
	return b.String()
}

func summarizePlans(plans []resourcePlan, errs []error) (created, updated, failed int) {
	for i, p := range plans {
		if p.action == actionUnchanged {
			continue
		}
		if errs[i] != nil {
			failed++
		} else if p.action == actionCreate {
			created++
		} else {
			updated++
		}
	}
	return
}

// --- Apply execution ---

func applyPlans(ctx context.Context, dynClient dynamic.Interface, plans []resourcePlan, force bool, ch chan<- applyResult) {
	defer close(ch)
	for i, p := range plans {
		if ctx.Err() != nil {
			return
		}
		if p.action == actionUnchanged {
			continue
		}

		var resource dynamic.ResourceInterface
		if p.mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			resource = dynClient.Resource(p.mapping.Resource).Namespace(p.obj.GetNamespace())
		} else {
			resource = dynClient.Resource(p.mapping.Resource)
		}

		jsonData, err := json.Marshal(p.obj)
		if err != nil {
			select {
			case ch <- applyResult{index: i, err: fmt.Errorf("marshal: %w", err)}:
			case <-ctx.Done():
				return
			}
			continue
		}

		f := force
		_, err = resource.Patch(ctx, p.obj.GetName(), types.ApplyPatchType, jsonData, metav1.PatchOptions{
			FieldManager: "apoxy-cli",
			Force:        &f,
		})
		select {
		case ch <- applyResult{index: i, err: err}:
		case <-ctx.Done():
			return
		}
	}
}

func applyPlain(ctx context.Context, dynClient dynamic.Interface, plans []resourcePlan, force bool) error {
	errs := make([]error, len(plans))
	for i, p := range plans {
		if p.action == actionUnchanged {
			fmt.Printf("  - %s (%s) unchanged\n", p.obj.GetName(), p.gvkStr)
			continue
		}

		var resource dynamic.ResourceInterface
		if p.mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			resource = dynClient.Resource(p.mapping.Resource).Namespace(p.obj.GetNamespace())
		} else {
			resource = dynClient.Resource(p.mapping.Resource)
		}

		jsonData, err := json.Marshal(p.obj)
		if err != nil {
			errs[i] = err
			fmt.Printf("  x %s (%s): %v\n", p.obj.GetName(), p.gvkStr, err)
			continue
		}

		f := force
		_, err = resource.Patch(ctx, p.obj.GetName(), types.ApplyPatchType, jsonData, metav1.PatchOptions{
			FieldManager: "apoxy-cli",
			Force:        &f,
		})
		errs[i] = err
		if err != nil {
			fmt.Printf("  x %s (%s): %v\n", p.obj.GetName(), p.gvkStr, err)
		} else {
			fmt.Printf("  applied %s (%s)\n", p.obj.GetName(), p.gvkStr)
		}
	}

	created, updated, failed := summarizePlans(plans, errs)
	fmt.Printf("\nDone: %d created, %d updated, %d failed.\n", created, updated, failed)
	if failed > 0 {
		return fmt.Errorf("%d resource(s) failed to apply", failed)
	}
	return nil
}

// --- Dry-run (preserves existing behavior) ---

func installControllerDryRun(ctx context.Context, dynClient dynamic.Interface, mapper meta.RESTMapper, yamlz []byte, ns string, force bool) error {
	drOutput := strings.Builder{}
	for _, y := range strings.Split(string(yamlz), "---") {
		if strings.TrimSpace(y) == "" {
			continue
		}

		obj := &unstructured.Unstructured{}
		_, gvk, err := decoder.Decode([]byte(y), nil, obj)
		if err != nil {
			return fmt.Errorf("failed to decode YAML: %w", err)
		}

		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return fmt.Errorf("failed to get REST mapping: %w", err)
		}

		if ns != "" && gvk.Group == "" && gvk.Kind == "Namespace" {
			obj.SetName(ns)
		}

		var resource dynamic.ResourceInterface
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			if ns != "" {
				obj.SetNamespace(ns)
			}
			resource = dynClient.Resource(mapping.Resource).Namespace(obj.GetNamespace())
		} else {
			resource = dynClient.Resource(mapping.Resource)
		}

		jsonData, err := json.Marshal(obj)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		prettyGVK := obj.GroupVersionKind().String()
		if prettyGVK[0] == '/' {
			prettyGVK = "core" + prettyGVK
		}

		f := force
		un, err := resource.Patch(ctx, obj.GetName(), types.ApplyPatchType, jsonData, metav1.PatchOptions{
			FieldManager: "apoxy-cli",
			Force:        &f,
			DryRun:       []string{metav1.DryRunAll},
		})
		if err != nil {
			return fmt.Errorf("failed to apply patch for %s (%s): %w", obj.GetName(), prettyGVK, err)
		}

		gvkEncoder := scheme.Codecs.EncoderForVersion(encoder, gvk.GroupVersion())
		yamlBytes, err := runtime.Encode(gvkEncoder, un)
		if err != nil {
			return fmt.Errorf("failed to encode YAML: %w", err)
		}
		drOutput.Write(yamlBytes)
		drOutput.WriteString("---\n")
	}

	fmt.Fprintf(os.Stderr, "Dry run complete.  No changes were made.\n")
	fmt.Print(drOutput.String())
	return nil
}

// --- Main orchestration ---

func installController(ctx context.Context, kc *rest.Config, yamlz []byte, ns string, dryRun, force, yes bool, kubeContext string) error {
	dc, err := discovery.NewDiscoveryClientForConfig(kc)
	if err != nil {
		return err
	}

	dynClient, err := dynamic.NewForConfig(kc)
	if err != nil {
		return err
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))

	if dryRun {
		return installControllerDryRun(ctx, dynClient, mapper, yamlz, ns, force)
	}

	plans, err := buildPlan(ctx, dynClient, mapper, yamlz, ns, force)
	if err != nil {
		return err
	}

	allUnchanged := true
	for _, p := range plans {
		if p.action != actionUnchanged {
			allUnchanged = false
			break
		}
	}
	if allUnchanged {
		fmt.Println("All resources up to date.")
		return nil
	}

	isTTY := term.IsTerminal(int(os.Stdout.Fd())) && term.IsTerminal(int(os.Stdin.Fd()))

	if isTTY {
		fmt.Println(renderPlan(plans))
		if !yes {
			confirmed, err := runConfirmation(kubeContext)
			if err != nil {
				return fmt.Errorf("confirmation: %w", err)
			}
			if !confirmed {
				fmt.Println("Aborted.")
				return nil
			}
		}

		applyCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		ch := make(chan applyResult)
		go applyPlans(applyCtx, dynClient, plans, force, ch)
		p := tea.NewProgram(newApplyModel(plans, ch))
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("apply: %w", err)
		}
	} else {
		printPlanPlain(plans)
		if !yes {
			return fmt.Errorf("non-interactive mode requires --yes flag")
		}
		if err := applyPlain(ctx, dynClient, plans, force); err != nil {
			return err
		}
	}

	return nil
}

var installK8sCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Apoxy Controller in Kubernetes",
	Long: `Install the Apoxy Controller into the target Kubernetes cluster.

This will create a new namespace and deploy the controller and supporting resources.  The controller
will automatically connect to the Apoxy API and begin managing your in-cluster Apoxy resources.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		kubeconfig, err := cmd.Flags().GetString("kubeconfig")
		if err != nil {
			return err
		}
		kubeconfig = resolveKubeconfigPath(kubeconfig)
		kubeContext, err := cmd.Flags().GetString("context")
		if err != nil {
			return err
		}

		kc, kubeContext, err := loadKubeClientConfig(kubeconfig, kubeContext)
		if err != nil {
			return err
		}

		namespace, err := cmd.Flags().GetString("namespace")
		if err != nil {
			return err
		}
		force, err := cmd.Flags().GetBool("force")
		if err != nil {
			return err
		}
		dryRun, err := cmd.Flags().GetBool("dry-run")
		if err != nil {
			return err
		}
		clusterName, err := cmd.Flags().GetString("cluster-name")
		if err != nil {
			return err
		}
		mirror, err := cmd.Flags().GetString("mirror")
		if err != nil {
			return err
		}
		yes, err := cmd.Flags().GetBool("yes")
		if err != nil {
			return err
		}

		// If --cluster-name wasn't explicitly provided, recover it from the
		// existing namespace's apoxy.dev/cluster-name annotation so the API
		// returns YAML consistent with the current install.
		if clusterName == "" {
			clientset, err := kubernetes.NewForConfig(kc)
			if err == nil {
				ns, err := clientset.CoreV1().Namespaces().Get(cmd.Context(), namespace, metav1.GetOptions{})
				if err == nil {
					if v, ok := ns.Annotations[clusterNameAnnotation]; ok {
						clusterName = v
					}
				}
			}
		}

		yamlz, err := getYAML(clusterName, mirror)
		if err != nil {
			return fmt.Errorf("failed to get YAML: %w", err)
		}

		if err := installController(cmd.Context(), kc, yamlz, namespace, dryRun, force, yes, kubeContext); err != nil {
			return fmt.Errorf("failed to install controller: %w", err)
		}

		return nil
	},
}

var k8sCmd = &cobra.Command{
	Use:   "k8s",
	Args:  cobra.NoArgs,
	Short: "Commands that manage Apoxy on Kubernetes",
}

func init() {
	installK8sCmd.Flags().String("kubeconfig", "", "Path to the kubeconfig file to use for Kubernetes API access")
	installK8sCmd.Flags().String("context", "", "Kubernetes context to use from the kubeconfig file")
	installK8sCmd.Flags().String("namespace", "apoxy", "The namespace to install the controller into")
	installK8sCmd.Flags().Bool("dry-run", false, "If true, only print the YAML that would be applied")
	installK8sCmd.Flags().Bool("force", false, "If true, forces value overwrites (See: https://v1-28.docs.kubernetes.io/docs/reference/using-api/server-side-apply/#conflicts)")
	installK8sCmd.Flags().String("cluster-name", "", "Cluster name identifier for multi-cluster deployments")
	installK8sCmd.Flags().String("mirror", "", "Mirror mode (gateway, ingress, all)")
	installK8sCmd.Flags().BoolP("yes", "y", false, "Skip confirmation and apply changes immediately")
	k8sCmd.AddCommand(installK8sCmd)

	RootCmd.AddCommand(k8sCmd)
}
