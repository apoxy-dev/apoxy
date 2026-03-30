package domain

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1alpha3 "github.com/apoxy-dev/apoxy/api/core/v1alpha3"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/rest"
)

// DomainRecordPreApply sets the DomainReplaceAnnotation when the user is
// changing a DomainRecord's type via apply. It lists existing records at the
// same spec.name and, if one exists with a different field key, marks it for
// replacement so the controller can atomically swap DNS and delete the old record.
func DomainRecordPreApply(ctx context.Context, dr *corev1alpha3.DomainRecord) error {
	newKey := dr.TargetFieldKey()
	if newKey == "" || dr.Spec.Name == "" {
		return nil
	}

	c, err := config.DefaultAPIClient()
	if err != nil {
		return fmt.Errorf("creating API client: %w", err)
	}

	list, err := c.CoreV1alpha3().DomainRecords().List(ctx, metav1.ListOptions{
		FieldSelector: "spec.name=" + dr.Spec.Name,
	})
	if err != nil {
		return fmt.Errorf("listing existing records for %s: %w", dr.Spec.Name, err)
	}

	for i := range list.Items {
		existing := &list.Items[i]
		if existing.Name == dr.GetName() {
			continue
		}
		existingKey := existing.TargetFieldKey()
		if existingKey != "" && existingKey != newKey {
			ann := dr.GetAnnotations()
			if ann == nil {
				ann = make(map[string]string)
			}
			ann[corev1alpha3.DomainReplaceAnnotation] = existing.Name
			dr.SetAnnotations(ann)
			break
		}
	}
	return nil
}

var domainRecordResource = &resource.ResourceCommand[*corev1alpha3.DomainRecord, *corev1alpha3.DomainRecordList]{
	Use:      "domain",
	Aliases:  []string{"d", "domains", "domainrecord", "domainrecords", "dr"},
	Short:    "Manage domain record objects",
	Long:     `Domain records configure DNS records and routing for your services.`,
	KindName: "domainrecord",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*corev1alpha3.DomainRecord, *corev1alpha3.DomainRecordList] {
		return c.CoreV1alpha3().DomainRecords()
	},
	TablePrinter: &resource.TablePrinterConfig[*corev1alpha3.DomainRecord, *corev1alpha3.DomainRecordList]{
		ObjToTable:  func(d *corev1alpha3.DomainRecord) resource.TableConverter { return d },
		ListToTable: func(l *corev1alpha3.DomainRecordList) resource.TableConverter { return l },
	},
	PreApply: DomainRecordPreApply,
	ListFlags: func(cmd *cobra.Command) func() string {
		var zone string
		cmd.Flags().StringVar(&zone, "zone", "", "Filter domain records by zone name.")
		return func() string {
			if zone != "" {
				return "spec.zone=" + zone
			}
			return ""
		}
	},
}

var zoneResource = &resource.ResourceCommand[*corev1alpha3.DomainZone, *corev1alpha3.DomainZoneList]{
	Use:      "zone",
	Aliases:  []string{"zones", "dz"},
	Short:    "Manage domain zone objects",
	Long:     `Domain zones represent DNS zones that domains are managed under.`,
	KindName: "domainzone",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*corev1alpha3.DomainZone, *corev1alpha3.DomainZoneList] {
		return c.CoreV1alpha3().DomainZones()
	},
	TablePrinter: &resource.TablePrinterConfig[*corev1alpha3.DomainZone, *corev1alpha3.DomainZoneList]{
		ObjToTable:  func(dz *corev1alpha3.DomainZone) resource.TableConverter { return dz },
		ListToTable: func(l *corev1alpha3.DomainZoneList) resource.TableConverter { return l },
	},
}

// Cmd returns the domain command with the zone subcommand attached.
func Cmd() *cobra.Command {
	cmd := domainRecordResource.Build()
	cmd.AddCommand(zoneResource.Build())
	return cmd
}
