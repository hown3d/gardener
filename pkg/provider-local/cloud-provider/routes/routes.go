package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
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

var ClusterCIDR netip.Prefix

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
		processErr, ok := errors.AsType[processError](err)
		if !ok {
			return err
		}

		stdout, err := io.ReadAll(processErr.stderr)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(stdout)) == "RTNETLINK answers: File exists" {
			klog.Info("route already exists")
			return nil
		}
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

	var routeErr error
	for _, pod := range machinePodList.Items {
		log := klog.FromContext(ctx).WithValues("targetNode", route.TargetNode, "operation", op, "pod", pod.Name)

		podIP, err := netip.ParseAddr(pod.Status.PodIP)
		if err != nil {
			return err
		}

		// skip route if target node is the pod itself
		if podIP.Compare(nodeInternalIP) == 0 {
			log.Info("pod is targetNode, skipping route")
			continue
		}
		cmd := []string{"ip", "route", string(op), route.DestinationCIDR, "via", nodeInternalIP.String(), "dev", "eth0", "onlink"}
		log.Info("modifyRoute", "cmd", strings.Join(cmd, " "))
		_, _, err = p.executeCommandInPod(ctx, pod.Name, cmd)
		if err != nil {
			routeErr = errors.Join(routeErr, fmt.Errorf("adding route in pod %s: %w", pod.Name, err))
		}

		nodeName := pod.Spec.NodeName
		containerID, err := p.containerIDByName(ctx, nodeName)
		if err != nil {
			return err
		}

		podLinkIndex, err := p.machinePodLinkIndex(ctx, pod.Name)
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

		if err := p.ensureIPRoute(ctx, op, containerID, route.DestinationCIDR, nodeInternalIP); err != nil {
			return fmt.Errorf("ensuring ip route on kind node %s: %w", nodeName, err)
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

	for nodeIP, node := range nodeMap {
		ipRoutes, err := p.listIPRoutes(ctx, node)
		if err != nil {
			return nil, fmt.Errorf("list ip routes of pod %s: %w", node, err)
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
					targetNode = node
				} else {
					klog.Infof("gateway %s is not a node", gateway)
					continue
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
			routeSet = nodeRouteSet.Intersection(routeSet)
		}

		klog.V(1).InfoS("new route set after intersection",
			"routeSet", routeSet.UnsortedList(),
			"nodeRouteSet", nodeRouteSet.UnsortedList(),
			"node", node)
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
func (p *Provider) ensureIPRule(ctx context.Context, nodeContainerID, machinePodIfName string) error {
	stdout, _, err := p.executeCommandInContainer(ctx, nodeContainerID, []string{"ip", "--json", "rule", "show", "iif", machinePodIfName, "lookup", strconv.Itoa(p.Config.Routes.TableID)})
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
	_, _, err = p.executeCommandInContainer(ctx, nodeContainerID, []string{"ip", "rule", "add", "iif", machinePodIfName, "lookup", strconv.Itoa(p.Config.Routes.TableID)})
	if err != nil {
		return err
	}
	return nil

}

// ensureIPRoute ensures an ip route in the outer node's container for each machine pod
func (p *Provider) ensureIPRoute(ctx context.Context, op op, nodeContainerID, destinationCIDR string, nodeIP netip.Addr) error {
	cmd := []string{"ip", "route", string(op), destinationCIDR, "via", nodeIP.String(), "table", strconv.Itoa(p.Config.Routes.TableID)}
	_, _, err := p.executeCommandInContainer(ctx, nodeContainerID, cmd)
	if err != nil {
		return err
	}
	return nil
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

type processError struct {
	code   int
	stderr io.Reader
	stdout io.Reader
}

func (e processError) Error() string {
	stdout, err := io.ReadAll(e.stdout)
	if err != nil {
		return err.Error()
	}

	stderr, err := io.ReadAll(e.stderr)
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("process exit with code %d\nstderr:\n%s\nstdout:\n%s\n", e.code, stderr, stdout)
}
