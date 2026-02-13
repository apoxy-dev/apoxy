package cmd

import (
	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/rest"
)

var proxyResource = &resource.ResourceCommand[*corev1alpha2.Proxy, *corev1alpha2.ProxyList]{
	Use:      "proxy",
	Aliases:  []string{"p", "proxies"},
	Short:    "Manage proxy objects",
	Long:     `The controllers object in the Apoxy API.`,
	KindName: "proxy",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*corev1alpha2.Proxy, *corev1alpha2.ProxyList] {
		return c.CoreV1alpha2().Proxies()
	},
	TablePrinter: &resource.TablePrinterConfig[*corev1alpha2.Proxy, *corev1alpha2.ProxyList]{
		ObjToTable:  func(p *corev1alpha2.Proxy) resource.TableConverter { return p },
		ListToTable: func(l *corev1alpha2.ProxyList) resource.TableConverter { return l },
	},
}

func init() {
	RootCmd.AddCommand(proxyResource.Build())
}
