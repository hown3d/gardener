// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package instances

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudproviderv1alpha1 "github.com/gardener/gardener/pkg/provider-local/cloud-provider/api/v1alpha1"
	"github.com/gardener/gardener/pkg/provider-local/cloud-provider/helper"
	machineproviderv1alpha1 "github.com/gardener/gardener/pkg/provider-local/machine-provider/api/v1alpha1"
)

// Provider implements the cloudprovider.InstancesV2 interface for the cloud-provider-local.
// Shoot nodes are backed by machine pods running in the runtime cluster (the kind cluster). A node's "instance" is the
// machine pod with the same name in the configured runtime cluster namespace.
type Provider struct {
	// Config is the full config of cloud-controller-manager-local.
	Config *cloudproviderv1alpha1.CloudProviderConfig

	// RuntimeClient is a Kubernetes client for the runtime cluster (seed) of the shoot cluster, i.e., the kind cluster
	// where the shoot machine pods run.
	RuntimeClient client.Client
}

// InstanceExists returns true if the instance for the given node exists according to the cloud provider.
// Use the node.name or node.spec.providerID field to find the node in the cloud provider.
func (p *Provider) InstanceExists(ctx context.Context, node *corev1.Node) (bool, error) {
	if _, err := p.getMachinePod(ctx, node); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// InstanceShutdown returns true if the instance is shutdown according to the cloud provider.
// Use the node.name or node.spec.providerID field to find the node in the cloud provider.
func (p *Provider) InstanceShutdown(ctx context.Context, node *corev1.Node) (bool, error) {
	pod, err := p.getMachinePod(ctx, node)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, cloudprovider.InstanceNotFound
		}
		return false, err
	}

	return isShutdown(pod), nil
}

// InstanceMetadata returns the instance's metadata. The values returned in InstanceMetadata are
// translated into specific fields and labels in the Node object on registration.
// Implementations should always check node.spec.providerID first when trying to discover the instance
// for a given node. In cases where node.spec.providerID is empty, implementations can use other
// properties of the node like its name, labels and annotations.
func (p *Provider) InstanceMetadata(ctx context.Context, node *corev1.Node) (*cloudprovider.InstanceMetadata, error) {
	pod, err := p.getMachinePod(ctx, node)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, cloudprovider.InstanceNotFound
		}
		return nil, err
	}

	klog.V(4).InfoS("Found machine pod for node", "node", node.Name, "pod", client.ObjectKeyFromObject(pod))

	addresses, err := helper.NodeAddresses(node, pod)
	if err != nil {
		return nil, err
	}

	return &cloudprovider.InstanceMetadata{
		// The provider ID must match what machine-controller-manager-provider-local reports for the machine, which is
		// the machine pod name. Both the machine's and the node's provider ID must be equal for cluster-autoscaler
		// to find the node group of a node.
		ProviderID:    pod.Name,
		InstanceType:  pod.Labels[machineproviderv1alpha1.LabelInstanceType],
		NodeAddresses: addresses,
		Zone:          pod.Labels[machineproviderv1alpha1.LabelZone],
		Region:        pod.Labels[machineproviderv1alpha1.LabelRegion],
	}, nil
}

// getMachinePod returns the machine pod backing the given node. It returns a NotFound error if the pod does not exist
// or is not a machine pod.
func (p *Provider) getMachinePod(ctx context.Context, node *corev1.Node) (*corev1.Pod, error) {
	if p.Config == nil || p.Config.RuntimeCluster == nil {
		return nil, fmt.Errorf("runtime cluster is not configured")
	}
	return helper.GetMachinePod(ctx, p.RuntimeClient, p.Config.RuntimeCluster.Namespace, node)
}

// isShutdown returns true if the machine pod is terminating or has terminated.
func isShutdown(pod *corev1.Pod) bool {
	if pod.DeletionTimestamp != nil {
		return true
	}

	switch pod.Status.Phase {
	case corev1.PodSucceeded, corev1.PodFailed:
		return true
	}

	return false
}
