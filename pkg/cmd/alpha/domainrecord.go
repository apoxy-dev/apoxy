package alpha

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	corev1alpha3 "github.com/apoxy-dev/apoxy/api/core/v1alpha3"
	"github.com/apoxy-dev/apoxy/client/versioned/scheme"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/rest"
)

// dnsTypeToFieldKey maps the user-visible DNS record type to the internal
// field key used in the metadata.name (e.g. "example.com--ips").
var dnsTypeToFieldKey = map[string]string{
	"a":      "a",
	"aaaa":   "aaaa",
	"cname":  "fqdn",
	"txt":    "txt",
	"mx":     "mx",
	"dkim":   "dkim",
	"spf":    "spf",
	"dmarc":  "dmarc",
	"caa":    "caa",
	"srv":    "srv",
	"ns":     "ns",
	"ds":     "ds",
	"dnskey": "dnskey",
	"ref":    "ref",
}

// domainRecordNameTransform converts "name/TYPE" (e.g. "example.com/A")
// into the internal metadata.name (e.g. "example.com--ips").
func domainRecordNameTransform(arg string) (string, error) {
	slash := strings.LastIndex(arg, "/")
	if slash == -1 || slash == 0 || slash == len(arg)-1 {
		return "", fmt.Errorf("name must be in the form <domain>/<record-type>, e.g. example.com/A")
	}
	name, typ := arg[:slash], arg[slash+1:]
	fieldKey, ok := dnsTypeToFieldKey[strings.ToLower(typ)]
	if !ok {
		return "", fmt.Errorf("unsupported record type %q; valid types: A, AAAA, CNAME, TXT, MX, DKIM, SPF, DMARC, CAA, SRV, NS, DS, DNSKEY, Ref", typ)
	}
	return fmt.Sprintf("%s--%s", name, fieldKey), nil
}

// domainRecordDefaultName derives the internal metadata.name from a
// DomainRecord's spec fields.
func domainRecordDefaultName(dr *corev1alpha3.DomainRecord) (string, error) {
	if dr.Spec.Name == "" {
		return "", fmt.Errorf("spec.name is required")
	}
	if dr.Spec.Target.Ref != nil {
		return fmt.Sprintf("%s--ref", dr.Spec.Name), nil
	}
	if dr.Spec.Target.DNS != nil {
		key := dr.Spec.Target.DNS.DNSFieldKey()
		if key == "" {
			return "", fmt.Errorf("spec.target.dns must have at least one populated field")
		}
		return fmt.Sprintf("%s--%s", dr.Spec.Name, key), nil
	}
	return "", fmt.Errorf("spec.target must have either dns or ref set")
}

func init() {
	resource.RegisterDefaultName(
		corev1alpha3.SchemeGroupVersion.WithKind("DomainRecord"),
		func(data []byte) (string, error) {
			obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
			if err != nil {
				return "", err
			}
			dr, ok := obj.(*corev1alpha3.DomainRecord)
			if !ok {
				return "", fmt.Errorf("unexpected type %T", obj)
			}
			return domainRecordDefaultName(dr)
		},
	)
}

var domainRecordResource = &resource.ResourceCommand[*corev1alpha3.DomainRecord, *corev1alpha3.DomainRecordList]{
	Use:      "domains",
	Aliases:  []string{"dr", "domainrecord", "domainrecords"},
	Short:    "Manage domain record objects",
	Long:     `Domain records configure individual DNS records within a domain zone.`,
	KindName: "domainrecord",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*corev1alpha3.DomainRecord, *corev1alpha3.DomainRecordList] {
		return c.CoreV1alpha3().DomainRecords()
	},
	TablePrinter: &resource.TablePrinterConfig[*corev1alpha3.DomainRecord, *corev1alpha3.DomainRecordList]{
		ObjToTable:  func(r *corev1alpha3.DomainRecord) resource.TableConverter { return r },
		ListToTable: func(l *corev1alpha3.DomainRecordList) resource.TableConverter { return l },
	},
	NameTransform:   domainRecordNameTransform,
	DefaultName: domainRecordDefaultName,
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
