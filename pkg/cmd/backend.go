package cmd

import (
	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/rest"
)

var backendResource = &resource.ResourceCommand[*corev1alpha2.Backend, *corev1alpha2.BackendList]{
	Use:      "backend",
	Aliases:  []string{"be", "backends"},
	Short:    "Manage backend objects",
	Long:     `Backends configure upstream endpoints for proxies.`,
	KindName: "backend",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*corev1alpha2.Backend, *corev1alpha2.BackendList] {
		return c.CoreV1alpha2().Backends()
	},
	TablePrinter: &resource.TablePrinterConfig[*corev1alpha2.Backend, *corev1alpha2.BackendList]{
		ObjToTable:  func(b *corev1alpha2.Backend) resource.TableConverter { return b },
		ListToTable: func(l *corev1alpha2.BackendList) resource.TableConverter { return l },
	},
}

func init() {
	RootCmd.AddCommand(backendResource.Build())
}
