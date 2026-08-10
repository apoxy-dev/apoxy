//go:build linux

package router

import (
	"errors"
	"fmt"
	"hash/fnv"
	"strconv"

	"github.com/vishvananda/netns"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"

	apoxynetns "github.com/apoxy-dev/apoxy/pkg/netns"
)

const overlayPortFilterComment = "apoxy-admin-underlay-only"

func overlayPortFilterChain(iface string) utiliptables.Chain {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(iface))
	return utiliptables.Chain(fmt.Sprintf("APOXY-ADM-%08X", hash.Sum32()))
}

func overlayPortFilterJumpRule(iface string, chain utiliptables.Chain) []string {
	return []string{
		"-i", iface,
		"-m", "comment",
		"--comment", overlayPortFilterComment,
		"-j", string(chain),
	}
}

func overlayPortFilterRule(port uint16) []string {
	return []string{
		"-p", "tcp",
		"--dport", strconv.Itoa(int(port)),
		"-j", "REJECT",
		"--reject-with", "tcp-reset",
	}
}

func installOverlayPortFilters(ns netns.NsHandle, iface string, ports []uint16) error {
	return apoxynetns.Do(ns, func() error {
		v4 := utiliptables.New(utiliptables.ProtocolIPv4)
		v6 := utiliptables.New(utiliptables.ProtocolIPv6)
		if err := ensureOverlayPortFilters(v4, v6, iface, ports); err != nil {
			_ = deleteOverlayPortFilters(v4, v6, iface)
			return err
		}
		return nil
	})
}

func removeOverlayPortFilters(ns netns.NsHandle, iface string) error {
	return apoxynetns.Do(ns, func() error {
		return deleteOverlayPortFilters(
			utiliptables.New(utiliptables.ProtocolIPv4),
			utiliptables.New(utiliptables.ProtocolIPv6),
			iface,
		)
	})
}

func ensureOverlayPortFilters(v4, v6 utiliptables.Interface, iface string, ports []uint16) error {
	for _, ipt := range []utiliptables.Interface{v4, v6} {
		family := "IPv4"
		if ipt.IsIPv6() {
			family = "IPv6"
		}
		chain := overlayPortFilterChain(iface)
		if _, err := ipt.EnsureChain(utiliptables.TableFilter, chain); err != nil {
			return fmt.Errorf("failed to create %s overlay filter chain: %w", family, err)
		}
		// Replace the chain contents so a force-stopped earlier process cannot
		// leave a different admin port blocked when this interface name is reused.
		if err := ipt.FlushChain(utiliptables.TableFilter, chain); err != nil {
			return fmt.Errorf("failed to reset %s overlay filter chain: %w", family, err)
		}
		for _, port := range ports {
			if _, err := ipt.EnsureRule(
				utiliptables.Append,
				utiliptables.TableFilter,
				chain,
				overlayPortFilterRule(port)...,
			); err != nil {
				return fmt.Errorf("failed to deny overlay TCP port %d for %s: %w", port, family, err)
			}
		}
		if _, err := ipt.EnsureRule(
			utiliptables.Prepend,
			utiliptables.TableFilter,
			utiliptables.ChainInput,
			overlayPortFilterJumpRule(iface, chain)...,
		); err != nil {
			return fmt.Errorf("failed to attach %s overlay filter chain: %w", family, err)
		}
	}
	return nil
}

func deleteOverlayPortFilters(v4, v6 utiliptables.Interface, iface string) error {
	var errs []error
	for _, ipt := range []utiliptables.Interface{v4, v6} {
		family := "IPv4"
		if ipt.IsIPv6() {
			family = "IPv6"
		}
		chain := overlayPortFilterChain(iface)
		if err := ipt.DeleteRule(
			utiliptables.TableFilter,
			utiliptables.ChainInput,
			overlayPortFilterJumpRule(iface, chain)...,
		); err != nil {
			errs = append(errs, fmt.Errorf("failed to detach %s overlay filter chain: %w", family, err))
		}
		exists, err := ipt.ChainExists(utiliptables.TableFilter, chain)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to inspect %s overlay filter chain: %w", family, err))
			continue
		}
		if !exists {
			continue
		}
		if err := ipt.FlushChain(utiliptables.TableFilter, chain); err != nil {
			errs = append(errs, fmt.Errorf("failed to flush %s overlay filter chain: %w", family, err))
			continue
		}
		if err := ipt.DeleteChain(utiliptables.TableFilter, chain); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete %s overlay filter chain: %w", family, err))
		}
	}
	return errors.Join(errs...)
}
