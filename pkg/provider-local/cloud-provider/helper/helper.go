package helper

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetMachinePods returns all pods backing machines.
func GetMachinePods(ctx context.Context, c client.Client, namespace string) (*corev1.PodList, error) {
	podList := &corev1.PodList{}
	if err := c.List(ctx, podList, client.InNamespace(namespace), client.MatchingLabels{"app": "machine"}); err != nil {
		return nil, err
	}

	return podList, nil
}

// GetMachinePod returns the machine pod backing the given node. It returns a NotFound error if the pod does not exist
// or is not a machine pod.
func GetMachinePod(ctx context.Context, c client.Client, namespace string, node *corev1.Node) (*corev1.Pod, error) {
	// Look up the machine pod using the providerID if already set. Fallback to the node name otherwise, e.g. for
	// initially populating the providerID. The machine provider uses the pod name as node name and provider ID.
	name := node.Spec.ProviderID
	if name == "" {
		name = node.Name
	}

	pod := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, pod); err != nil {
		return nil, err
	}

	if pod.Labels["app"] != "machine" {
		return nil, apierrors.NewNotFound(corev1.Resource("pods"), name)
	}

	return pod, nil
}

// nodeAddresses returns the node addresses for the given machine pod. The pod IPs are reported as internal IPs,
// ordered such that the IP family of the node's current primary internal IP comes first. This preserves the IP family
// preference of the kubelet (e.g., configured via --node-ip="::" for IPv6-preferred shoots), because the order of the
// pod IPs is determined by the primary IP family of the runtime cluster, which may differ from the shoot's.
func NodeAddresses(node *corev1.Node, pod *corev1.Pod) ([]corev1.NodeAddress, error) {
	// check if the node's current primary internal IP is IPv6
	var preferIPv6 bool

	for _, address := range node.Status.Addresses {
		if address.Type != corev1.NodeInternalIP {
			continue
		}
		ip, err := netip.ParseAddr(address.Address)
		if err != nil {
			return nil, fmt.Errorf("invalid node internal IP %q: %w", address.Address, err)
		}
		preferIPv6 = ip.Is6()
		break
	}

	// collect all pod IPs
	var (
		ips       = make([]netip.Addr, 0, len(pod.Status.PodIPs))
		allErrors error
	)

	for _, podIP := range pod.Status.PodIPs {
		ip, err := netip.ParseAddr(podIP.IP)
		if err != nil {
			allErrors = errors.Join(allErrors, fmt.Errorf("invalid pod IP %q: %w", podIP, err))
			continue
		}
		ips = append(ips, ip)
	}

	if allErrors != nil {
		return nil, allErrors
	}

	// preserve the IP family preference of the kubelet
	slices.SortStableFunc(ips, func(a, b netip.Addr) int {
		if a.Is6() == b.Is6() {
			return 0
		}
		if a.Is6() == preferIPv6 {
			return -1
		}
		return 1
	})

	// return the pod IPs as node internal IPs + the pod name as node hostname
	addresses := make([]corev1.NodeAddress, 0, len(ips)+1)
	for _, ip := range ips {
		addresses = append(addresses, corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: ip.String()})
	}
	if len(addresses) == 0 {
		// Without any IPs, we must not report the hostname only, otherwise the node controller would drop the internal
		// IPs determined by the kubelet.
		return nil, nil
	}

	return append(addresses, corev1.NodeAddress{Type: corev1.NodeHostName, Address: pod.Name}), nil
}
