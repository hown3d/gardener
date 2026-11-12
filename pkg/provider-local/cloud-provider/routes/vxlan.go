package routes

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

var (
	vtepMACBase  net.HardwareAddr
	vtepIPPrefix = netip.MustParsePrefix("10.254.0.0/24")
)

// vxlanMTUSize is the MTU used for routes in the machine pod that are routed to another machine pod running on a different kind node.
// The current base MTU is 1480 and we subtract 50 bytes for the VXLAN header
const vxlanMTUSize = "1430"

func init() {
	var err error
	vtepMACBase, err = net.ParseMAC("02:42:0a:fe:64:00")
	if err != nil {
		panic(err)
	}
}

type tunnelInfo struct {
	nodeIP   netip.Addr
	tunnelIP netip.Addr
	mac      net.HardwareAddr
}

func (p *Provider) getNodeVXLANTunnelInfos(ctx context.Context, nodes []corev1.Node) (map[string]tunnelInfo, error) {
	m := make(map[string]tunnelInfo, len(nodes))
	vni, err := strconv.Atoi(p.tableID)
	if err != nil {
		return nil, fmt.Errorf("parsing table id to vni: %w", err)
	}
	for i, node := range nodes {
		vxlanTunnelIP, vxlanMAC, err := p.ensureVXLANDevice(ctx, node.Name, vni, i+1)
		if err != nil {
			return nil, fmt.Errorf("ensuring vxlan device: %w", err)
		}
		nodeIP, err := getNodeInternalIP(node.Status.Addresses)
		if err != nil {
			return nil, err
		}
		m[node.Name] = tunnelInfo{
			tunnelIP: vxlanTunnelIP,
			mac:      vxlanMAC,
			nodeIP:   nodeIP,
		}
	}
	return m, nil
}

func (p *Provider) ensureVXLANDevice(ctx context.Context, nodeName string, vni int, index int) (netip.Addr, net.HardwareAddr, error) {
	cmd := []string{"ip", "link", "add", p.vxlanDeviceName, "type", "vxlan", "id", strconv.Itoa(vni), "dev", "eth0", "dstport", "4789", "nolearning"}
	_, _, err := p.containerExecutor.Execute(ctx, nodeName, cmd)
	if err != nil {
		if !isFileAlreadyExists(err) {
			return netip.Addr{}, net.HardwareAddr{}, fmt.Errorf("creating vxlan device: %w", err)
		}
	}

	vtepMac, err := allocateVtepMac(uint8(index))
	if err != nil {
		return netip.Addr{}, vtepMac, fmt.Errorf("allocating vtep mac: %w", err)
	}
	_, _, err = p.containerExecutor.Execute(ctx, nodeName, []string{"ip", "link", "set", p.vxlanDeviceName, "address", vtepMac.String()})
	if err != nil {
		if !isFileAlreadyExists(err) {
			return netip.Addr{}, vtepMac, fmt.Errorf("set mac address for vxlan device: %w", err)
		}
	}

	vtepIP, err := allocateVtepIP(index)
	if err != nil {
		return vtepIP, vtepMac, fmt.Errorf("allocating vtep IP: %w", err)
	}
	_, _, err = p.containerExecutor.Execute(ctx, nodeName, []string{"ip", "addr", "add", netip.PrefixFrom(vtepIP, 32).String(), "dev", "lo"})
	if err != nil {
		if !isAddressAlreadyAssigned(err) {
			return vtepIP, vtepMac, fmt.Errorf("setting ip %s on loopback device %s: %w", vtepIP, p.vxlanDeviceName, err)
		}
	}

	_, _, err = p.containerExecutor.Execute(ctx, nodeName, []string{"ip", "link", "set", p.vxlanDeviceName, "up"})
	if err != nil {
		return vtepIP, vtepMac, fmt.Errorf("setting vxlan device up: %w", err)
	}

	_, _, err = p.containerExecutor.Execute(ctx, nodeName, []string{"sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", p.vxlanDeviceName)})
	if err != nil {
		return vtepIP, vtepMac, fmt.Errorf("disable rpfilter on vxlan device: %w", err)
	}

	return vtepIP, vtepMac, nil
}

func (p *Provider) ensureVXLANEndpoints(ctx context.Context, nodeTunnelMap map[string]tunnelInfo, nodes []corev1.Node) error {
	for _, node := range nodes {
		for otherNode, info := range nodeTunnelMap {
			if otherNode == node.Name {
				continue
			}
			_, _, err := p.containerExecutor.Execute(ctx, node.Name, []string{
				"bridge", "fdb", "append", info.mac.String(), "dev", p.vxlanDeviceName, "dst", info.nodeIP.String(),
			})
			if err != nil {
				return fmt.Errorf("appending to bridge: %w", err)
			}

			_, _, err = p.containerExecutor.Execute(ctx, node.Name, []string{
				"ip", "neigh", "add", info.tunnelIP.String(), "lladdr", info.mac.String(), "dev", p.vxlanDeviceName, "nud", "permanent",
			})
			if err != nil {
				if !isFileAlreadyExists(err) {
					return fmt.Errorf("setting neighbor for tunnel ip: %w", err)
				}
			}
		}
	}
	return nil
}

func allocateVtepIP(nodeIndex int) (netip.Addr, error) {
	vtepIP := vtepIPPrefix.Addr()
	for range nodeIndex {
		vtepIP = vtepIP.Next()
	}
	if !vtepIP.IsValid() {
		return netip.Addr{}, fmt.Errorf("getting vtep IP, allocation failed")
	}
	return vtepIP, nil
}

func allocateVtepMac(nodeIndex uint8) (net.HardwareAddr, error) {
	if len(vtepMACBase) != 6 {
		return net.HardwareAddr{}, fmt.Errorf("malformed base mac %s", vtepMACBase)
	}
	base := [6]byte(vtepMACBase)
	base[5] = nodeIndex
	return net.HardwareAddr(base[:]), nil
}
