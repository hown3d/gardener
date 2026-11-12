package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"

	"k8s.io/klog/v2"
)

type ipLink struct {
	IfIndex   int    `json:"ifindex"`
	LinkIndex int    `json:"link_index"`
	IfName    string `json:"ifname"`
	Address   string `json:"address"`
}

type ipRule struct {
	IIF         string          `json:"iif"`
	Table       string          `json:"table"`
	DetachedIIF json.RawMessage `json:"iif_detached"`
}

func (r ipRule) IsIIFDetached() bool {
	return r.DetachedIIF != nil
}

type ipRoute struct {
	Dest    string `json:"dst"`
	Gateway string `json:"gateway"`
	Device  string `json:"dev"`
}

func (p *Provider) deleteIPRoute(ctx context.Context, exec executor, name, destinationCIDR, tableID string) error {
	cmd := []string{"ip", "route", "delete", destinationCIDR}
	if tableID != "" {
		cmd = append(cmd, "table", tableID)
	}
	_, _, err := exec.Execute(ctx, name, cmd)
	if err != nil && !isNoSuchProcess(err) {
		return fmt.Errorf("deleting route: %w", err)
	}
	return nil
}
func (p *Provider) listIPRoutes(ctx context.Context, exec executor, name string) ([]ipRoute, error) {
	cmd := []string{"ip", "--json", "route", "list"}
	stdout, _, err := exec.Execute(ctx, name, cmd)
	if err != nil {
		return nil, fmt.Errorf("get route list of container: %w", err)
	}
	buf := new(bytes.Buffer)
	stdout = io.TeeReader(stdout, buf)
	routes := []ipRoute{}
	if err := json.NewDecoder(stdout).Decode(&routes); err != nil {
		return nil, fmt.Errorf("decoding ip route list json output: %w", err)
	}
	klog.V(1).Infof("ip route output: %s", buf.String())
	return routes, nil
}

func (p *Provider) createIPRoute(ctx context.Context, exec executor, name, destinationCIDR, mtu, device, tableID string, gatewayIP netip.Addr, onlink bool) error {
	cmd := []string{"ip", "route", "add", destinationCIDR, "via", gatewayIP.String()}
	if tableID != "" {
		cmd = append(cmd, "table", tableID)
	}
	if mtu != "" {
		cmd = append(cmd, "mtu", mtu)
	}
	if device != "" {
		cmd = append(cmd, "dev", device)
	}
	if onlink {
		cmd = append(cmd, "onlink")
	}
	_, _, err := exec.Execute(ctx, name, cmd)
	if err != nil && !isFileAlreadyExists(err) {
		return fmt.Errorf("adding route: %w", err)
	}
	return nil
}

func (p *Provider) listIPLinks(ctx context.Context, exec executor, name string, filter ...string) ([]ipLink, error) {
	cmd := []string{"ip", "--json", "link", "show"}
	cmd = append(cmd, filter...)
	stdout, _, err := exec.Execute(ctx, name, cmd)
	if err != nil {
		return nil, err
	}
	ipLinks := []ipLink{}
	if err := json.NewDecoder(stdout).Decode(&ipLinks); err != nil {
		return nil, err
	}
	return ipLinks, err
}

func (p *Provider) listIPRules(ctx context.Context, exec executor, name string, filter ...string) ([]ipRule, error) {
	cmd := []string{"ip", "--json", "rule", "show"}
	cmd = append(cmd, filter...)
	stdout, _, err := exec.Execute(ctx, name, cmd)
	if err != nil {
		return nil, err
	}

	var rules []ipRule
	if err := json.NewDecoder(stdout).Decode(&rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func (p *Provider) createIPRule(ctx context.Context, exec executor, name string, ifname string) error {
	_, _, err := exec.Execute(ctx, name, []string{"ip", "rule", "add", "iif", ifname, "lookup", p.tableID})
	if err != nil && !isFileAlreadyExists(err) {
		return err
	}
	return nil
}

func (p *Provider) deleteIPRule(ctx context.Context, exec executor, name string, rule ipRule) error {
	_, _, err := exec.Execute(ctx, name, []string{"ip", "rule", "delete", "iif", rule.IIF, "lookup", rule.Table})
	if err != nil && !isNoSuchProcess(err) {
		return err
	}
	return nil
}

// ensureIPRoute ensures an ip rule in the outer node's container for each machine pod to lookup the correct routing table
func (p *Provider) ensureIPRuleOnKindNode(ctx context.Context, kindNode, ifname string) error {
	rules, err := p.listIPRules(ctx, p.containerExecutor, kindNode, "iif", ifname, "lookup", p.tableID)
	if err != nil {
		return err
	}

	// TODO: validate table ID is correct
	if len(rules) != 0 {
		return nil
	}

	return p.createIPRule(ctx, p.containerExecutor, kindNode, ifname)
}

// ensureIPRouteOnKindNode ensures an ip route in the outer node's container for each machine pod
func (p *Provider) ensureIPRouteOnKindNode(ctx context.Context, kindNode, destinationCIDR string, nodeIP netip.Addr, dev string, onlink bool) error {
	return p.createIPRoute(ctx, p.containerExecutor, kindNode, destinationCIDR, "", dev, p.tableID, nodeIP, onlink)
}
