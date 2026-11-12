package routes

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/provider-local/cloud-provider/helper"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dockerclient "github.com/docker/docker/client"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/klog/v2"
)

var (
	ClusterCIDR netip.Prefix
)

func NewProvider(runtimeClient client.Client, dockerClient dockerclient.APIClient, podExecutor kubernetes.PodExecutor, tableID, namespace string) *Provider {
	return &Provider{
		RuntimeClient:     runtimeClient,
		containerExecutor: NewContainerExecutor(dockerClient),
		podExecutor:       NewPodExecutor(namespace, podExecutor),
		namespace:         namespace,
		vxlanDeviceName:   "vxlan" + tableID,
		tableID:           tableID,
	}
}

// Provider implements the cloudprovider.LoadBalancer interface for the cloud-provider-local.
type Provider struct {
	// RuntimeClient is a Kubernetes client for the runtime cluster (seed) of the shoot cluster, i.e., the kind cluster
	// where the shoot machine pods run. This is only set if the cloud-controller-manager-local is running for a shoot
	// cluster, not for the kind cluster itself.
	RuntimeClient client.Client

	namespace         string
	containerExecutor executor
	podExecutor       executor
	vxlanDeviceName   string
	tableID           string
}

// CreateRoute implements [cloudprovider.Routes].
func (p *Provider) CreateRoute(ctx context.Context, clusterName string, nameHint string, route *cloudprovider.Route) error {
	return p.createRoute(ctx, route)
}

// DeleteRoute implements [cloudprovider.Routes].
func (p *Provider) DeleteRoute(ctx context.Context, clusterName string, route *cloudprovider.Route) error {
	return p.deleteRoute(ctx, route)
}

// ListRoutes implements [cloudprovider.Routes].
func (p *Provider) ListRoutes(ctx context.Context, clusterName string) ([]*cloudprovider.Route, error) {
	machinePods, err := p.machinePodMap(ctx)
	if err != nil {
		return nil, err
	}

	type route struct {
		Node string
		Cidr string
		IP   string
	}

	routeSet := sets.New[route]()

	for podIP, machinePodName := range machinePods {
		ipRoutes, err := p.listIPRoutes(ctx, p.podExecutor, machinePodName)
		if err != nil {
			return nil, fmt.Errorf("list ip routes of pod %s: %w", machinePodName, err)
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

			targetMachinePod, ok := machinePods[gateway]
			if !ok {
				if iproute.Device == "cilium_host" {
					iproute.Gateway = podIP.String()
					targetMachinePod = machinePodName
				} else {
					klog.Infof("gateway %s is not a live node, reporting stale route for deletion", gateway)
				}
			}
			nodeRouteSet = nodeRouteSet.Insert(route{
				Node: targetMachinePod,
				IP:   iproute.Gateway,
				Cidr: iproute.Dest,
			})
		}

		// union ensures that we only report routes that are present on all nodes.
		// Otherwise reconcile must recreate the route, so that every node has the route in it's table.
		if routeSet.Len() == 0 {
			routeSet = nodeRouteSet
		} else {
			routeSet = nodeRouteSet.Union(routeSet)
		}

		klog.V(1).InfoS("new route set after union",
			"routeSet", routeSet.UnsortedList(),
			"nodeRouteSet", nodeRouteSet.UnsortedList(),
			"node", machinePodName)
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

func (p *Provider) deleteRoute(ctx context.Context, route *cloudprovider.Route) error {
	// targetNode will be empty, as we do not know the target node name anymore since the node object is gone and also the pod is gone
	if err := p.deleteRouteInMachinePods(ctx, route); err != nil {
		return fmt.Errorf("deleting route in machine pods: %w", err)
	}
	if err := p.deleteRouteInKindNodes(ctx, route); err != nil {
		return fmt.Errorf("delete route in kind nodes: %w", err)
	}
	return nil
}

func (p *Provider) deleteRouteInKindNodes(ctx context.Context, route *cloudprovider.Route) error {
	nodeList := &corev1.NodeList{}
	if err := p.RuntimeClient.List(ctx, nodeList); err != nil {
		return err
	}

	for _, node := range nodeList.Items {
		if err := p.deleteRuleInKindNode(ctx, node.Name); err != nil {
			return fmt.Errorf("delete rule in kind node %s: %w", node.Name, err)
		}

		if err := p.deleteIPRoute(ctx, p.containerExecutor, node.Name, route.DestinationCIDR, p.tableID); err != nil {
			return fmt.Errorf("deleting ip route on kind node %s: %w", node.Name, err)
		}
	}
	return nil
}

func (p *Provider) deleteRuleInKindNode(ctx context.Context, nodeName string) error {
	rules, err := p.listIPRules(ctx, p.containerExecutor, nodeName, "table", p.tableID)
	if err != nil {
		return err
	}

	for _, r := range rules {
		if !r.IsIIFDetached() {
			continue
		}
		if err := p.deleteIPRule(ctx, p.containerExecutor, nodeName, r); err != nil {
			return fmt.Errorf("deleting orphaned ip rule: %w", err)
		}
	}
	return nil
}

func (p *Provider) deleteRouteInMachinePods(ctx context.Context, route *cloudprovider.Route) error {
	machinePodList, err := helper.GetMachinePods(ctx, p.RuntimeClient, p.namespace)
	if err != nil {
		return err
	}

	for _, machine := range machinePodList.Items {
		if err := p.deleteIPRoute(ctx, p.podExecutor, machine.Name, route.DestinationCIDR, ""); err != nil {
			return fmt.Errorf("deleting route in machine %s: %w", machine.Name, err)
		}
	}

	return err
}

func (p *Provider) createRoute(ctx context.Context, route *cloudprovider.Route) error {
	targetNodeInternalIP, err := getNodeInternalIP(route.TargetNodeAddresses)
	if err != nil {
		return err
	}

	machinePodList, err := helper.GetMachinePods(ctx, p.RuntimeClient, p.namespace)
	if err != nil {
		return err
	}

	nodeList := &corev1.NodeList{}
	if err := p.RuntimeClient.List(ctx, nodeList); err != nil {
		return err
	}

	slices.SortFunc(nodeList.Items, func(a, b corev1.Node) int {
		return strings.Compare(a.Name, b.Name)
	})

	nodeTunnelMap, err := p.getNodeVXLANTunnelInfos(ctx, nodeList.Items)
	if err != nil {
		return fmt.Errorf("getting vxlan tunnel infos from nodes: %w", err)
	}

	if err := p.ensureVXLANEndpoints(ctx, nodeTunnelMap, nodeList.Items); err != nil {
		return fmt.Errorf("ensuring vxlan endpoints: %w", err)
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
		log := klog.FromContext(ctx).WithValues("targetNode", route.TargetNode)

		machinePodName := info.Name
		nodeName := info.NodeName
		podIP, err := netip.ParseAddr(podIP)
		if err != nil {
			return err
		}
		destinationInfo := podIPToInfo[targetNodeInternalIP.String()]

		// skip route if target node is the pod itself
		if podIP.Compare(targetNodeInternalIP) != 0 {
			var mtu string
			if destinationInfo.NodeName != nodeName {
				mtu = vxlanMTUSize
			}
			if err := p.createIPRoute(ctx, p.podExecutor, machinePodName, route.DestinationCIDR, mtu, "eth0", targetNodeInternalIP, true); err != nil {
				return fmt.Errorf("create route in machine pod %s: %w", machinePodName, err)
			}
		}

		if destinationInfo.NodeName == nodeName {
			log.Info("same node")
			if err := p.ensureRouteTargetMachineOnSameKindNode(ctx, machinePodName, nodeName, route.DestinationCIDR, targetNodeInternalIP); err != nil {
				return fmt.Errorf("ensuring route on same kind node: %w", err)
			}
		} else {
			log.Info("other node")
			if destinationInfo.NodeName == "" {
				return fmt.Errorf("no machine pod known for target node internal IP %s (route %s)", targetNodeInternalIP, route.DestinationCIDR)
			}
			tunnelInfo, ok := nodeTunnelMap[destinationInfo.NodeName]
			if !ok {
				return fmt.Errorf("tunnel map doesn't contain entry for destination node %s", destinationInfo.NodeName)
			}
			if err := p.ensureRouteTargetMachineOnOtherKindNode(ctx, nodeName, nodeName, route.DestinationCIDR, tunnelInfo.tunnelIP); err != nil {
				return fmt.Errorf("ensuring route to other kind node: %w", err)
			}
		}
	}

	return routeErr
}

// ensureRouteToOtherKindNode sets up a route for destinationCIDR to the machine pods veth device
func (p *Provider) ensureRouteTargetMachineOnSameKindNode(ctx context.Context, machinePodName, kindNode, destinationCIDR string, targetNodeIP netip.Addr) error {
	podLinkIndex, err := p.machinePodLinkIndex(ctx, machinePodName)
	if err != nil {
		return fmt.Errorf("getting machine pod link index: %w", err)
	}

	machinePodifName, err := p.machinePodLinkName(ctx, kindNode, podLinkIndex)
	if err != nil {
		return fmt.Errorf("getting machine pod link name: %w", err)
	}

	if err := p.ensureIPRuleOnKindNode(ctx, kindNode, machinePodifName); err != nil {
		return fmt.Errorf("ensuring ip rule: %w", err)
	}

	if err := p.ensureIPRouteOnKindNode(ctx, kindNode, destinationCIDR, targetNodeIP, "", false); err != nil {
		return fmt.Errorf("ensuring ip route: %w", err)
	}
	return nil
}

// ensureRouteTargetMachineOnOtherKindNode sets up a route for destinationCIDR through the vxlan device for nodeName using tunnelIP of the remote kind node
func (p *Provider) ensureRouteTargetMachineOnOtherKindNode(ctx context.Context, nodeName, kindNodeContainerID, destinationCIDR string, tunnelIP netip.Addr) error {
	if err := p.ensureIPRuleOnKindNode(ctx, kindNodeContainerID, p.vxlanDeviceName); err != nil {
		return fmt.Errorf("ensuring vxlan ip rule on kind node %s: %w", nodeName, err)
	}
	if err := p.ensureIPRouteOnKindNode(ctx, kindNodeContainerID, destinationCIDR, tunnelIP, p.vxlanDeviceName, true); err != nil {
		return fmt.Errorf("ensuring vxlan ip route on kind node %s: %w", nodeName, err)
	}
	return nil
}

// machinePodLinkIndex returns the link index of the machine pods veth pair
func (p *Provider) machinePodLinkIndex(ctx context.Context, podName string) (int, error) {
	ipLinks, err := p.listIPLinks(ctx, p.podExecutor, podName, "eth0")
	if err != nil {
		return 0, err
	}

	if len(ipLinks) != 1 {
		return 0, fmt.Errorf("no ip route found for eth0")
	}

	return ipLinks[0].LinkIndex, nil
}

// machinePodLinkName gets the link name of the machine's pod veth pair on the node.
// nodeContainerID is the id of the docker container running as node in the kind cluster.
func (p *Provider) machinePodLinkName(ctx context.Context, node string, podLinkIndex int) (string, error) {
	ipLinks, err := p.listIPLinks(ctx, p.containerExecutor, node)
	if err != nil {
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

// machinePodMap returns a map keyed by the machine's pod IP mapped to it's pod name
func (p *Provider) machinePodMap(ctx context.Context) (map[netip.Addr]string, error) {
	podList, err := helper.GetMachinePods(ctx, p.RuntimeClient, p.namespace)
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

func getNodeInternalIP(nodeAddresses []corev1.NodeAddress) (netip.Addr, error) {
	for _, address := range nodeAddresses {
		if address.Type != corev1.NodeInternalIP {
			continue
		}
		return netip.ParseAddr(address.Address)
	}
	return netip.Addr{}, fmt.Errorf("no internal address found")
}
