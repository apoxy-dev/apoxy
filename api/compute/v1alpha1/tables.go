package v1alpha1

import (
	"context"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

var (
	_ resourcestrategy.TableConverter = &Service{}
	_ resourcestrategy.TableConverter = &ServiceList{}
	_ resourcestrategy.TableConverter = &ServiceRevision{}
	_ resourcestrategy.TableConverter = &ServiceRevisionList{}
	_ resourcestrategy.TableConverter = &EgressGateway{}
	_ resourcestrategy.TableConverter = &EgressGatewayList{}
	_ resourcestrategy.TableConverter = &EgressRoute{}
	_ resourcestrategy.TableConverter = &EgressRouteList{}
)

// formatAge formats a time as a Kubernetes-style age string (e.g., "5m", "2h", "7d").
func formatAge(t time.Time) string {
	if t.IsZero() {
		return "<unknown>"
	}
	return duration.ShortHumanDuration(time.Since(t))
}

// noHeaders reports whether the caller asked for a headerless table.
func noHeaders(tableOptions runtime.Object) bool {
	opt, ok := tableOptions.(*metav1.TableOptions)
	return ok && opt.NoHeaders
}

// setListMeta copies list metadata onto a rendered table.
func setListMeta(table *metav1.Table, listMeta *metav1.ListMeta) {
	table.ResourceVersion = listMeta.ResourceVersion
	table.Continue = listMeta.Continue
	table.RemainingItemCount = listMeta.RemainingItemCount
}

// readyConditionString reports a Ready-style condition's status, or "Unknown"
// when the controller hasn't reconciled the object yet.
func readyConditionString(conditions []metav1.Condition, condType string) string {
	c := meta.FindStatusCondition(conditions, condType)
	if c == nil {
		return "Unknown"
	}
	return string(c.Status)
}

// =============================================================================
// Service
// =============================================================================

// serviceStatusString summarizes the Ready condition as a single status word:
// "Ready" when serving, the condition's reason (falling back to "NotReady")
// when not, and "Pending" before the controller's first pass.
func serviceStatusString(svc *Service) string {
	c := meta.FindStatusCondition(svc.Status.Conditions, ConditionReady)
	if c == nil {
		return "Pending"
	}
	if c.Status == metav1.ConditionTrue {
		return "Ready"
	}
	if c.Reason != "" {
		return c.Reason
	}
	return "NotReady"
}

func serviceColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Name of the service"},
		{Name: "Status", Type: "string", Description: "Whether the intended revision is serving"},
		{Name: "Age", Type: "string", Description: "Time since creation"},
	}
}

func serviceRow(svc *Service) metav1.TableRow {
	return metav1.TableRow{
		Cells: []interface{}{
			svc.Name,
			serviceStatusString(svc),
			formatAge(svc.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: svc},
	}
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (s *Service) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = serviceColumns()
	}
	table.Rows = append(table.Rows, serviceRow(s))
	table.ResourceVersion = s.ResourceVersion
	return table, nil
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (sl *ServiceList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = serviceColumns()
	}
	for i := range sl.Items {
		table.Rows = append(table.Rows, serviceRow(&sl.Items[i]))
	}
	setListMeta(table, &sl.ListMeta)
	return table, nil
}

// =============================================================================
// ServiceRevision
// =============================================================================

// serviceRevisionOwnerString returns the owning Service's name. ServiceRevisionSpec
// carries no back-reference, so the owner is read from metadata.ownerReferences.
func serviceRevisionOwnerString(rev *ServiceRevision) string {
	for _, ref := range rev.OwnerReferences {
		if ref.Kind == "Service" {
			return ref.Name
		}
	}
	return "-"
}

// serviceRevisionDigestString shortens a resolved "sha256:..." digest to a
// docker-style 12-char prefix, falling back to the tag when unresolved.
func serviceRevisionDigestString(rev *ServiceRevision) string {
	digest := rev.Spec.Bundle.Digest
	if digest == "" {
		if rev.Spec.Bundle.Tag != "" {
			return rev.Spec.Bundle.Tag
		}
		return "-"
	}
	if i := strings.Index(digest, ":"); i >= 0 && len(digest) >= i+13 {
		return digest[:i+13]
	}
	return digest
}

func serviceRevisionColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Name of the revision"},
		{Name: "Service", Type: "string", Description: "Owning Service"},
		{Name: "Digest", Type: "string", Description: "Resolved bundle digest (or tag when unresolved)"},
		{Name: "Ready", Type: "string", Description: "Whether the revision is materialized"},
		{Name: "Age", Type: "string", Description: "Time since creation"},
	}
}

func serviceRevisionRow(rev *ServiceRevision) metav1.TableRow {
	return metav1.TableRow{
		Cells: []interface{}{
			rev.Name,
			serviceRevisionOwnerString(rev),
			serviceRevisionDigestString(rev),
			readyConditionString(rev.Status.Conditions, ConditionReady),
			formatAge(rev.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: rev},
	}
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (r *ServiceRevision) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = serviceRevisionColumns()
	}
	table.Rows = append(table.Rows, serviceRevisionRow(r))
	table.ResourceVersion = r.ResourceVersion
	return table, nil
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (rl *ServiceRevisionList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = serviceRevisionColumns()
	}
	for i := range rl.Items {
		table.Rows = append(table.Rows, serviceRevisionRow(&rl.Items[i]))
	}
	setListMeta(table, &rl.ListMeta)
	return table, nil
}

// =============================================================================
// EgressGateway
// =============================================================================

func egressGatewayColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Name of the gateway"},
		{Name: "Default Policy", Type: "string", Description: "Policy applied to unmatched egress traffic"},
		{Name: "Listeners", Type: "integer", Description: "Number of interception listeners"},
		{Name: "Ready", Type: "string", Description: "Whether the gateway is programmed"},
		{Name: "Age", Type: "string", Description: "Time since creation"},
	}
}

func egressGatewayRow(gw *EgressGateway) metav1.TableRow {
	policy := string(gw.Spec.DefaultPolicy)
	if policy == "" {
		policy = "-"
	}
	return metav1.TableRow{
		Cells: []interface{}{
			gw.Name,
			policy,
			len(gw.Spec.Listeners),
			readyConditionString(gw.Status.Conditions, EgressGatewayConditionReady),
			formatAge(gw.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: gw},
	}
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (g *EgressGateway) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = egressGatewayColumns()
	}
	table.Rows = append(table.Rows, egressGatewayRow(g))
	table.ResourceVersion = g.ResourceVersion
	return table, nil
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (gl *EgressGatewayList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = egressGatewayColumns()
	}
	for i := range gl.Items {
		table.Rows = append(table.Rows, egressGatewayRow(&gl.Items[i]))
	}
	setListMeta(table, &gl.ListMeta)
	return table, nil
}

// =============================================================================
// EgressRoute
// =============================================================================

// egressRouteParentsString renders spec.parentRefs as "name" or
// "name:sectionName" when a route attaches to a single listener.
func egressRouteParentsString(route *EgressRoute) string {
	if len(route.Spec.ParentRefs) == 0 {
		return "-"
	}
	parts := make([]string, len(route.Spec.ParentRefs))
	for i, p := range route.Spec.ParentRefs {
		name := string(p.Name)
		if p.SectionName != nil && *p.SectionName != "" {
			name += ":" + string(*p.SectionName)
		}
		parts[i] = name
	}
	return strings.Join(parts, ",")
}

func egressRouteMatchCount(route *EgressRoute) int {
	n := 0
	for _, rule := range route.Spec.Rules {
		n += len(rule.Matches)
	}
	return n
}

// egressRouteAcceptedString summarizes status.parents[].conditions[Accepted]
// across every parent: "Unknown" until the controller has reported on all of
// them, "True" only when every parent accepted the route, else "False".
func egressRouteAcceptedString(route *EgressRoute) string {
	if len(route.Status.Parents) == 0 {
		return "Unknown"
	}
	accepted := true
	for _, p := range route.Status.Parents {
		cond := meta.FindStatusCondition(p.Conditions, ConditionAccepted)
		if cond == nil {
			return "Unknown"
		}
		if cond.Status != metav1.ConditionTrue {
			accepted = false
		}
	}
	if accepted {
		return "True"
	}
	return "False"
}

func egressRouteColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Name of the route"},
		{Name: "Parents", Type: "string", Description: "Parent EgressGateway(s), optionally :listener"},
		{Name: "Matches", Type: "integer", Description: "Total destination matches across rules"},
		{Name: "Accepted", Type: "string", Description: "Whether every parent accepted the route"},
		{Name: "Age", Type: "string", Description: "Time since creation"},
	}
}

func egressRouteRow(route *EgressRoute) metav1.TableRow {
	return metav1.TableRow{
		Cells: []interface{}{
			route.Name,
			egressRouteParentsString(route),
			egressRouteMatchCount(route),
			egressRouteAcceptedString(route),
			formatAge(route.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: route},
	}
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (r *EgressRoute) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = egressRouteColumns()
	}
	table.Rows = append(table.Rows, egressRouteRow(r))
	table.ResourceVersion = r.ResourceVersion
	return table, nil
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (rl *EgressRouteList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = egressRouteColumns()
	}
	for i := range rl.Items {
		table.Rows = append(table.Rows, egressRouteRow(&rl.Items[i]))
	}
	setListMeta(table, &rl.ListMeta)
	return table, nil
}
