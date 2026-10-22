// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
)

// Interface is the dedicated interface of the relay and its two addresses.
type Interface struct {
	// Name is the name of the link.
	Name string
	// MAC is the MAC address of the link.
	MAC net.HardwareAddr
	// Own are the addresses of the relay on the link, with the length of the on-link prefix.
	// Other relays use them.
	Own []netip.Prefix
	// Public are the addresses that agents dial.
	Public []netip.Addr
	// Gateways are the next-hop routers of the link.
	Gateways []netip.Addr
}

// FindInterface gives the dedicated interface of cfg and its addresses. With IMDS it reads
// IMDSv2 of the instance; opts change the IMDS client.
func FindInterface(ctx context.Context, cfg *configv1alpha1.RelayInterface, opts ...func(*imds.Options)) (Interface, error) {
	if cfg == nil {
		return Interface{}, errors.New("no relay interface in the config")
	}
	switch cfg.Source {
	case configv1alpha1.RelayInterfaceSourceIMDS:
		if cfg.MAC != "" || len(cfg.Addresses) > 0 || len(cfg.Gateways) > 0 {
			return Interface{}, errors.New("mac, addresses and gateways are only for source Static")
		}
		// IMDSv2 only: no fallback to requests without a session token.
		opts = append([]func(*imds.Options){func(o *imds.Options) { o.EnableFallback = aws.FalseTernary }}, opts...)
		return fromIMDS(ctx, imds.New(imds.Options{}, opts...))
	case configv1alpha1.RelayInterfaceSourceStatic:
		return fromStatic(cfg)
	default:
		return Interface{}, fmt.Errorf("relay interface source %q is not IMDS or Static", cfg.Source)
	}
}

// fromIMDS reads the ENI with device number 1 and its addresses.
func fromIMDS(ctx context.Context, c *imds.Client) (Interface, error) {
	const macs = "network/interfaces/macs/"
	list, err := metadata(ctx, c, macs)
	if err != nil {
		return Interface{}, err
	}
	var mac string
	for _, m := range list {
		m = strings.TrimSuffix(m, "/")
		dev, err := metadata(ctx, c, macs+m+"/device-number")
		if err != nil {
			return Interface{}, err
		}
		if len(dev) == 1 && dev[0] == "1" {
			mac = m
			break
		}
	}
	if mac == "" {
		return Interface{}, errors.New("IMDS has no network interface with device number 1")
	}
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return Interface{}, fmt.Errorf("IMDS MAC %q: %w", mac, err)
	}
	locals, err := metadata(ctx, c, macs+mac+"/local-ipv4s")
	if err != nil {
		return Interface{}, err
	}
	subnets, err := metadata(ctx, c, macs+mac+"/subnet-ipv4-cidr-block")
	if err != nil {
		return Interface{}, err
	}
	publics, err := metadata(ctx, c, macs+mac+"/public-ipv4s")
	if err != nil && !notFound(err) {
		return Interface{}, err
	}
	if len(locals) == 0 || len(subnets) == 0 {
		return Interface{}, fmt.Errorf("IMDS has no private IPv4 or subnet for MAC %s", mac)
	}
	local, err := netip.ParseAddr(locals[0])
	if err != nil {
		return Interface{}, fmt.Errorf("IMDS local-ipv4s of MAC %s: %w", mac, err)
	}
	subnet, err := netip.ParsePrefix(subnets[0])
	if err != nil || !subnet.Contains(local) {
		return Interface{}, fmt.Errorf("IMDS subnet %q of MAC %s does not contain %s", subnets[0], mac, local)
	}
	ifc := Interface{
		MAC: hw,
		Own: []netip.Prefix{netip.PrefixFrom(local, subnet.Bits())},
		// The IPv4 gateway of an AWS subnet is the subnet base + 1.
		Gateways: []netip.Addr{subnet.Masked().Addr().Next()},
	}
	if len(publics) > 0 {
		pub, err := netip.ParseAddr(publics[0])
		if err != nil {
			return Interface{}, fmt.Errorf("IMDS public-ipv4s of MAC %s: %w", mac, err)
		}
		ifc.Public = []netip.Addr{pub}
	}
	ifc.Name, err = linkByMAC(hw)
	return ifc, err
}

// fromStatic uses the MAC, addresses and gateways of cfg. The own and the public addresses are
// both the addresses.
func fromStatic(cfg *configv1alpha1.RelayInterface) (Interface, error) {
	hw, err := net.ParseMAC(cfg.MAC)
	if err != nil {
		return Interface{}, fmt.Errorf("relay interface mac: %w", err)
	}
	if len(cfg.Addresses) == 0 {
		return Interface{}, errors.New("relay interface has no addresses")
	}
	ifc := Interface{MAC: hw}
	for _, s := range cfg.Addresses {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Interface{}, fmt.Errorf("relay interface address: %w", err)
		}
		ifc.Own = append(ifc.Own, p)
		ifc.Public = append(ifc.Public, p.Addr())
	}
	for _, s := range cfg.Gateways {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return Interface{}, fmt.Errorf("relay interface gateway: %w", err)
		}
		ifc.Gateways = append(ifc.Gateways, a)
	}
	ifc.Name, err = linkByMAC(hw)
	return ifc, err
}

// metadata returns the lines of an IMDS metadata path.
func metadata(ctx context.Context, c *imds.Client, path string) ([]string, error) {
	out, err := c.GetMetadata(ctx, &imds.GetMetadataInput{Path: path})
	if err != nil {
		return nil, fmt.Errorf("failed to read IMDS %s: %w", path, err)
	}
	defer out.Content.Close()
	b, err := io.ReadAll(out.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to read IMDS %s: %w", path, err)
	}
	var lines []string
	for _, l := range bytes.Split(b, []byte("\n")) {
		if l = bytes.TrimSpace(l); len(l) > 0 {
			lines = append(lines, string(l))
		}
	}
	return lines, nil
}

func notFound(err error) bool {
	var re *smithyhttp.ResponseError
	return errors.As(err, &re) && re.HTTPStatusCode() == http.StatusNotFound
}

// linkByMAC returns the name of the link with MAC hw.
func linkByMAC(hw net.HardwareAddr) (string, error) {
	links, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to list links: %w", err)
	}
	for _, l := range links {
		if bytes.Equal(l.HardwareAddr, hw) {
			return l.Name, nil
		}
	}
	return "", fmt.Errorf("no link has MAC %s", hw)
}
