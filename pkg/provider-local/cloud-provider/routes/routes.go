package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/gardener/gardener/pkg/client/kubernetes"
	cloudproviderv1alpha1 "github.com/gardener/gardener/pkg/provider-local/cloud-provider/api/v1alpha1"
	"github.com/gardener/gardener/pkg/provider-local/cloud-provider/helper"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/exec"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/klog/v2"
)

var (
	ClusterCIDR netip.Prefix

	vtepMACBase  net.HardwareAddr
	vtepIPPrefix = netip.MustParsePrefix("10.254.0.0/24")
)

func init() {
	var err error
	vtepMACBase, err = net.ParseMAC("02:42:0a:fe:64:00")
	if err != nil {
		panic(err)
	}
}

// Provider implements the cloudprovider.LoadBalancer interface for the cloud-provider-local.
type Provider struct {
	// Config is the full config of cloud-controller-manager-local.
	Config *cloudproviderv1alpha1.CloudProviderConfig

	// RuntimeClient is a Kubernetes client for the runtime cluster (seed) of the shoot cluster, i.e., the kind cluster
	// where the shoot machine pods run. This is only set if the cloud-controller-manager-local is running for a shoot
	// cluster, not for the kind cluster itself.
	RuntimeClient client.Client

	// DockerClient is the client connected to the host's Docker socket.
	DockerClient *dockerclient.Client

	PodExecutor kubernetes.PodExecutor
}

// CreateRoute implements [cloudprovider.Routes].
func (p *Provider) CreateRoute(ctx context.Context, clusterName string, nameHint string, route *cloudprovider.Route) error {
	if err := p.modifyRoute(ctx, opCreate, route); err != nil {
		if isFileAlreadyExists(err) {
			klog.Info("route already exists")
			return nil
		}
		return err
	}
	return nil
}

// DeleteRoute implements [cloudprovider.Routes].
func (p *Provider) DeleteRoute(ctx context.Context, clusterName string, route *cloudprovider.Route) error {
	if err := p.modifyRoute(ctx, opDelete, route); err != nil {
		processErr, ok := errors.AsType[processError](err)
		if !ok {
			return err
		}

		stdout, err := io.ReadAll(processErr.stderr)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(stdout)) == "RTNETLINK answers: No such process" {
			klog.Info("route already gone")
			return nil
		}
	}
	return nil
}

type op string

const (
	opDelete = "delete"
	opCreate = "add"
)

func (p *Provider) modifyRoute(ctx context.Context, op op, route *cloudprovider.Route) error {
	var nodeInternalIP netip.Addr
	for _, nodeAddr := range route.TargetNodeAddresses {
		if nodeAddr.Type != corev1.NodeInternalIP {
			continue
		}
		nodeInternalIP = netip.MustParseAddr(nodeAddr.Address)
	}
	if !nodeInternalIP.IsValid() {
		panic("node internal ip not found")
	}

	machinePodList, err := helper.GetMachinePods(ctx, p.RuntimeClient, p.Config.RuntimeCluster.Namespace)
	if err != nil {
		return err
	}

	nodeList := &corev1.NodeList{}
	if err := p.RuntimeClient.List(ctx, nodeList); err != nil {
		return err
	}
	type tunnelInfo struct {
		nodeIP   netip.Addr
		tunnelIP netip.Addr
		mac      net.HardwareAddr
	}
	nodeTunnelMap := map[string]tunnelInfo{}

	vxlanDeviceName := fmt.Sprintf("vxlan%d", p.Config.Routes.TableID)
	slices.SortFunc(nodeList.Items, func(a, b corev1.Node) int {
		return strings.Compare(a.Name, b.Name)
	})
	for i, node := range nodeList.Items {
		containerID, err := p.containerIDByName(ctx, node.Name)
		if err != nil {
			return err
		}
		vxlanTunnelIP, vxlanMAC, err := p.ensureVXLANDevice(ctx, containerID, vxlanDeviceName, p.Config.Routes.TableID, i+1)
		if err != nil {
			return fmt.Errorf("ensuring vxlan device: %w", err)
		}
		nodeIP, err := getNodeInternalIP(&node)
		if err != nil {
			return err
		}
		nodeTunnelMap[node.Name] = tunnelInfo{
			tunnelIP: vxlanTunnelIP,
			mac:      vxlanMAC,
			nodeIP:   nodeIP,
		}
	}

	// setup vxlan endpoints on every node
	for _, node := range nodeList.Items {
		containerID, err := p.containerIDByName(ctx, node.Name)
		if err != nil {
			return err
		}
		for otherNode, info := range nodeTunnelMap {
			if otherNode == node.Name {
				continue
			}
			_, _, err = p.executeCommandInContainer(ctx, containerID, []string{
				"bridge", "fdb", "append", info.mac.String(), "dev", vxlanDeviceName, "dst", info.nodeIP.String(),
			})
			if err != nil {
				return fmt.Errorf("appending to bridge: %w", err)
			}

			_, _, err = p.executeCommandInContainer(ctx, containerID, []string{
				"ip", "neigh", "add", info.tunnelIP.String(), "lladdr", info.mac.String(), "dev", vxlanDeviceName, "nud", "permanent",
			})
			if err != nil {
				if !isFileAlreadyExists(err) {
					return fmt.Errorf("setting neighbor for tunnel ip: %w", err)
				}
			}

		}
	}

	type podInfo struct {
		NodeName string
		Name     string
	}

	// key = podIP
	podIPToInfo := map[string]podInfo{}

	var routeErr error
	for _, pod := range machinePodList.Items {
		if pod.Spec.NodeName == "" {
			return fmt.Errorf("machine pod %s is not yet scheduled", pod.Name)
		}
		podIPToInfo[pod.Status.PodIP] = podInfo{
			NodeName: pod.Spec.NodeName,
			Name:     pod.Name,
		}
	}
	for podIP, info := range podIPToInfo {
		log := klog.FromContext(ctx).WithValues("targetNode", route.TargetNode, "operation", op)

		podName := info.Name
		nodeName := info.NodeName
		podIP, err := netip.ParseAddr(podIP)
		if err != nil {
			return err
		}

		// skip route if target node is the pod itself
		if podIP.Compare(nodeInternalIP) != 0 {
			cmd := []string{"ip", "route", string(op), route.DestinationCIDR, "via", nodeInternalIP.String(), "dev", "eth0", "onlink"}
			log.Info("modifyRoute", "cmd", strings.Join(cmd, " "))
			_, _, err = p.executeCommandInPod(ctx, podName, cmd)
			if err != nil {
				if !isFileAlreadyExists(err) {
					routeErr = errors.Join(routeErr, fmt.Errorf("adding route in pod %s: %w", podName, err))
				}
			}
		}

		destinationInfo := podIPToInfo[nodeInternalIP.String()]
		containerID, err := p.containerIDByName(ctx, nodeName)
		if err != nil {
			return err
		}
		if destinationInfo.NodeName == nodeName {
			log.Info("same node")

			podLinkIndex, err := p.machinePodLinkIndex(ctx, podName)
			if err != nil {
				return fmt.Errorf("getting machine pod link index: %w", err)
			}

			machinePodifName, err := p.machinePodLinkName(ctx, containerID, podLinkIndex)
			if err != nil {
				return fmt.Errorf("getting machine pod link name: %w", err)
			}

			if err := p.ensureIPRule(ctx, containerID, machinePodifName); err != nil {
				return fmt.Errorf("ensuring ip rule on kind node %s: %w", nodeName, err)
			}

			if err := p.ensureIPRoute(ctx, op, containerID, route.DestinationCIDR, nodeInternalIP, "", false); err != nil {
				return fmt.Errorf("ensuring ip route on kind node %s: %w", nodeName, err)
			}
		} else {
			tunnelInfo, ok := nodeTunnelMap[destinationInfo.NodeName]
			if !ok {
				return fmt.Errorf("tunnel map doesn't contain entry for %s", destinationInfo.NodeName)
			}
			log.Info("other node")
			if err := p.ensureIPRule(ctx, containerID, vxlanDeviceName); err != nil {
				return fmt.Errorf("ensuring vxlan ip rule on kind node %s: %w", nodeName, err)
			}
			if err := p.ensureIPRoute(ctx, op, containerID, route.DestinationCIDR, tunnelInfo.tunnelIP, vxlanDeviceName, true); err != nil {
				return fmt.Errorf("ensuring vxlan ip route on kind node %s: %w", nodeName, err)
			}

		}

	}

	return routeErr
}

// ListRoutes implements [cloudprovider.Routes].
func (p *Provider) ListRoutes(ctx context.Context, clusterName string) ([]*cloudprovider.Route, error) {
	nodeMap, err := p.nodeMap(ctx)
	if err != nil {
		return nil, err
	}

	type route struct {
		Node string
		Cidr string
		IP   string
	}

	routeSet := sets.New[route]()

	for nodeIP, podName := range nodeMap {
		ipRoutes, err := p.listIPRoutes(ctx, podName)
		if err != nil {
			return nil, fmt.Errorf("list ip routes of pod %s: %w", podName, err)
		}

		nodeRouteSet := sets.New[route]()
		for _, iproute := range ipRoutes {
			if iproute.Dest == "" || iproute.Gateway == "" {
				continue
			}
			destPrefix, err := netip.ParsePrefix(iproute.Dest)
			if err != nil {
				continue
			}
			if !ClusterCIDR.Overlaps(destPrefix) {
				klog.Infof("route dest %s does not match cluster pod cidr, skipping", destPrefix)
				continue
			}

			gateway, err := netip.ParseAddr(iproute.Gateway)
			if err != nil {
				return nil, err
			}

			targetNode, ok := nodeMap[gateway]
			if !ok {
				if iproute.Device == "cilium_host" {
					iproute.Gateway = nodeIP.String()
					targetNode = podName
				} else {
					klog.Infof("gateway %s is not a live node, reporting stale route for deletion", gateway)
					targetNode = gateway.String()
				}
			}
			nodeRouteSet = nodeRouteSet.Insert(route{
				Node: targetNode,
				IP:   iproute.Gateway,
				Cidr: iproute.Dest,
			})
		}

		// intersection ensures that we only report routes that are present on all nodes.
		// Otherwise reconcile must recreate the route, so that every node has the route in it's table.
		if routeSet.Len() == 0 {
			routeSet = nodeRouteSet
		} else {
			routeSet = nodeRouteSet.Union(routeSet)
		}

		klog.V(1).InfoS("new route set after union",
			"routeSet", routeSet.UnsortedList(),
			"nodeRouteSet", nodeRouteSet.UnsortedList(),
			"node", podName)
	}

	routeList := routeSet.UnsortedList()
	cloudproviderRoutes := make([]*cloudprovider.Route, 0, len(routeList))
	for _, r := range routeList {
		cloudproviderRoutes = append(cloudproviderRoutes, &cloudprovider.Route{
			TargetNode: types.NodeName(r.Node),
			TargetNodeAddresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: r.IP,
				},
				{
					Type:    corev1.NodeHostName,
					Address: r.Node,
				},
			},
			EnableNodeAddresses: true,
			DestinationCIDR:     r.Cidr,
		})
	}

	return cloudproviderRoutes, nil
}

// machinePodLinkIndex returns the link index of the machine pods veth pair
func (p *Provider) machinePodLinkIndex(ctx context.Context, podName string) (int, error) {
	stdout, _, err := p.executeCommandInPod(ctx, podName, []string{"ip", "--json", "link", "show", "eth0"})
	if err != nil {
		return 0, err
	}

	ipLinks := []ipLink{}
	if err := json.NewDecoder(stdout).Decode(&ipLinks); err != nil {
		return 0, err
	}

	if len(ipLinks) != 1 {
		return 0, fmt.Errorf("no ip route found for eth0")
	}

	return ipLinks[0].LinkIndex, nil
}

// machinePodLinkName gets the link name of the machine's pod veth pair on the node.
// nodeContainerID is the id of the docker container running as node in the kind cluster.
func (p *Provider) machinePodLinkName(ctx context.Context, nodeContainerID string, podLinkIndex int) (string, error) {
	stdout, _, err := p.executeCommandInContainer(ctx, nodeContainerID, []string{"ip", "--json", "link", "show"})
	if err != nil {
		return "", err
	}
	ipLinks := []ipLink{}
	if err := json.NewDecoder(stdout).Decode(&ipLinks); err != nil {
		return "", err
	}
	var ifName string
	for _, link := range ipLinks {
		if link.IfIndex == podLinkIndex {
			ifName = link.IfName
			break
		}
	}

	if ifName == "" {
		return "", fmt.Errorf("ifname for link index %d not found", podLinkIndex)
	}
	return ifName, nil
}

// ensureIPRoute ensures an ip rule in the outer node's container for each machine pod to lookup the correct routing table
func (p *Provider) ensureIPRule(ctx context.Context, nodeContainerID, ifname string) error {
	stdout, _, err := p.executeCommandInContainer(ctx, nodeContainerID, []string{"ip", "--json", "rule", "show", "iif", ifname, "lookup", strconv.Itoa(p.Config.Routes.TableID)})
	if err != nil {
		return err
	}

	rules := []ipRule{}
	if err := json.NewDecoder(stdout).Decode(&rules); err != nil {
		return err
	}

	// TODO: validate table ID is correct
	if len(rules) != 0 {
		return nil
	}
	_, _, err = p.executeCommandInContainer(ctx, nodeContainerID, []string{"ip", "rule", "add", "iif", ifname, "lookup", strconv.Itoa(p.Config.Routes.TableID)})
	if err != nil {
		return err
	}
	return nil

}

// ensureIPRoute ensures an ip route in the outer node's container for each machine pod
func (p *Provider) ensureIPRoute(ctx context.Context, op op, nodeContainerID, destinationCIDR string, nodeIP netip.Addr, dev string, onlink bool) error {
	cmd := []string{"ip", "route", string(op), destinationCIDR}
	if nodeIP.IsValid() {
		cmd = append(cmd, "via", nodeIP.String())
	}
	cmd = append(cmd, "table", strconv.Itoa(p.Config.Routes.TableID))
	if dev != "" {
		cmd = append(cmd, "dev", dev)
	}
	if onlink {
		cmd = append(cmd, "onlink")
	}
	_, _, err := p.executeCommandInContainer(ctx, nodeContainerID, cmd)
	if err != nil {
		if !isFileAlreadyExists(err) {
			return err
		}
	}
	return nil
}

func (p *Provider) ensureVXLANDevice(ctx context.Context, nodeContainerID, deviceName string, vni int, index int) (netip.Addr, net.HardwareAddr, error) {
	cmd := []string{"ip", "link", "add", deviceName, "type", "vxlan", "id", strconv.Itoa(vni), "dev", "eth0", "dstport", "4789", "nolearning"}
	_, _, err := p.executeCommandInContainer(ctx, nodeContainerID, cmd)
	if err != nil {
		if !isFileAlreadyExists(err) {
			return netip.Addr{}, net.HardwareAddr{}, fmt.Errorf("creating vxlan device: %w", err)
		}
	}

	vtepMac, err := allocateVtepMac(uint8(index))
	if err != nil {
		return netip.Addr{}, vtepMac, fmt.Errorf("allocating vtep mac: %w", err)
	}
	_, _, err = p.executeCommandInContainer(ctx, nodeContainerID, []string{"ip", "link", "set", deviceName, "address", vtepMac.String()})
	if err != nil {
		if !isFileAlreadyExists(err) {
			return netip.Addr{}, vtepMac, fmt.Errorf("set mac address for vxlan device: %w", err)
		}
	}

	vtepIP, err := allocateVtepIP(index)
	if err != nil {
		return vtepIP, vtepMac, fmt.Errorf("allocating vtep IP: %w", err)
	}
	_, _, err = p.executeCommandInContainer(ctx, nodeContainerID, []string{"ip", "addr", "add", netip.PrefixFrom(vtepIP, 32).String(), "dev", "lo"})
	if err != nil {
		if !isAddressAlreadyAssigned(err) {
			return vtepIP, vtepMac, fmt.Errorf("setting ip %s on loopback device %s: %w", vtepIP, deviceName, err)
		}
	}

	_, _, err = p.executeCommandInContainer(ctx, nodeContainerID, []string{"ip", "link", "set", deviceName, "up"})
	if err != nil {
		return vtepIP, vtepMac, fmt.Errorf("setting vxlan device up: %w", err)
	}

	_, _, err = p.executeCommandInContainer(ctx, nodeContainerID, []string{"sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", deviceName)})
	if err != nil {
		return vtepIP, vtepMac, fmt.Errorf("disable rpfilter on vxlan device: %w", err)
	}

	return vtepIP, vtepMac, nil
}

func (p *Provider) nodeMap(ctx context.Context) (map[netip.Addr]string, error) {
	podList, err := helper.GetMachinePods(ctx, p.RuntimeClient, p.Config.RuntimeCluster.Namespace)
	if err != nil {
		return nil, err
	}
	m := make(map[netip.Addr]string, len(podList.Items))

	for _, pod := range podList.Items {
		podIP, err := netip.ParseAddr(pod.Status.PodIP)
		if err != nil {
			return nil, err
		}
		m[podIP] = pod.Name
	}
	return m, nil
}

type ipLink struct {
	IfIndex   int    `json:"ifindex"`
	LinkIndex int    `json:"link_index"`
	IfName    string `json:"ifname"`
	Address   string `json:"address"`
}

type ipRule struct {
	IIF   string `json:"iif"`
	Table string `json:"table"`
}

type ipRoute struct {
	Dest    string `json:"dst"`
	Gateway string `json:"gateway"`
	Device  string `json:"dev"`
}

func (p *Provider) listIPRoutes(ctx context.Context, podName string) ([]ipRoute, error) {
	cmd := []string{"ip", "--json", "route", "list"}
	stdout, _, err := p.executeCommandInPod(ctx, podName, cmd)
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

func (p *Provider) executeCommandInPod(ctx context.Context, podName string, cmd []string) (io.Reader, io.Reader, error) {
	klog.V(1).Infof("running command %v on pod %s", cmd, podName)
	stdout, stderr, err := p.PodExecutor.Execute(ctx, p.Config.RuntimeCluster.Namespace, podName, "", cmd...)
	if err != nil {
		if exitErr, ok := errors.AsType[exec.CodeExitError](err); ok && exitErr.Exited() {
			return nil, nil, processError{code: exitErr.Code, stderr: stderr, stdout: stdout}
		}
		return nil, nil, err
	}
	return stdout, stderr, nil
}

func (p *Provider) executeCommandInContainer(ctx context.Context, containerID string, cmd []string) (io.Reader, io.Reader, error) {
	klog.V(1).Infof("running command %v on container %s", cmd, containerID)
	res, err := p.DockerClient.ContainerExecCreate(ctx, containerID, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("exec create: %w", err)
	}

	attachRes, err := p.DockerClient.ContainerExecAttach(ctx, res.ID, container.ExecAttachOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("exec attach: %w", err)
	}

	var stdout, stderr bytes.Buffer
	_, err = stdcopy.StdCopy(&stdout, &stderr, attachRes.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("demultiplex output: %w", err)
	}

	inspectRes, err := p.DockerClient.ContainerExecInspect(ctx, res.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("exec inspect: %w", err)
	}
	if inspectRes.ExitCode != 0 {
		return nil, nil, processError{code: inspectRes.ExitCode, stderr: &stderr, stdout: &stdout}
	}
	return &stdout, &stderr, nil
}

func (p *Provider) containerIDByName(ctx context.Context, name string) (string, error) {
	filters := filters.NewArgs(filters.Arg("name", name))
	containers, err := p.DockerClient.ContainerList(ctx, container.ListOptions{
		Filters: filters,
	})
	if err != nil {
		return "", err
	}
	if len(containers) == 0 {
		return "", fmt.Errorf("container list returned 0 items")
	}
	if len(containers) == 1 {
		return containers[0].ID, nil
	}
	for _, c := range containers {
		for _, n := range c.Names {
			n, _ := strings.CutPrefix(n, "/")
			if n == name {
				return c.ID, nil
			}
		}
	}
	return "", fmt.Errorf("container with name %s not found", name)
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

func getNodeInternalIP(node *corev1.Node) (netip.Addr, error) {
	for _, address := range node.Status.Addresses {
		if address.Type != corev1.NodeInternalIP {
			continue
		}
		return netip.ParseAddr(address.Address)
	}
	return netip.Addr{}, fmt.Errorf("no internal address found")
}
