package etcd

import (
	"context"
	"net"

	druidcorev1alpha1 "github.com/gardener/etcd-druid/api/core/v1alpha1"
	"k8s.io/client-go/rest"
)

func NewNoOp() Interface {
	return &noopETCD{}
}

type noopETCD struct {
}

// Deploy a component.
func (n *noopETCD) Deploy(ctx context.Context) error {
	return nil
}

// Destroy already deployed component.
func (n *noopETCD) Destroy(ctx context.Context) error {
	return nil
}

// Wait for deployment to finish and component to report ready.
func (n *noopETCD) Wait(ctx context.Context) error {
	return nil
}

// WaitCleanup for destruction to finish and component to be fully removed.
func (n *noopETCD) WaitCleanup(ctx context.Context) error {
	return nil
}

// Snapshot triggers the backup-restore sidecar to perform a full snapshot in case backup configuration is provided.
func (n *noopETCD) Snapshot(context.Context, rest.HTTPClient) error {
	return nil
}

// SetBackupConfig sets the backup configuration.
func (n *noopETCD) SetBackupConfig(config *BackupConfig) {
}

// Get retrieves the Etcd resource
func (n *noopETCD) Get(context.Context) (*druidcorev1alpha1.Etcd, error) {
	return nil, nil
}

// Scale scales the etcd resource to the given replica count.
func (n *noopETCD) Scale(context.Context, int32) error {
	return nil
}

// RolloutPeerCA gets the peer CA and patches the
// related `etcd` resource to use this new CA for peer communication.
func (n *noopETCD) RolloutPeerCA(context.Context) error {
	return nil
}

// IsPeerCARolledOut checks if the Etcd resource was annotated with credentials.gardener.cloud/peer-ca-rolled-out.
func (n *noopETCD) IsPeerCARolledOut(context.Context) (bool, error) {
	return false, nil
}

// MarkAsPeerCARolloutCompleted annotates the Etcd resource with credentials.gardener.cloud/peer-ca-rolled-out=true.
func (n *noopETCD) MarkAsPeerCARolloutCompleted(context.Context) error {
	return nil
}

// UnmarkAsPeerCARolloutCompleted removes the credentials.gardener.cloud/peer-ca-rolled-out annotation from the Etcd resource.
func (n *noopETCD) UnmarkAsPeerCARolloutCompleted(context.Context) error {
	return nil
}

// GetValues returns the current configuration values of the deployer.
func (n *noopETCD) GetValues() Values {
	return Values{}
}

// GetReplicas gets the Replicas field in the Values.
func (n *noopETCD) GetReplicas() *int32 {
	return nil
}

// SetReplicas sets the Replicas field in the Values.
func (n *noopETCD) SetReplicas(*int32) {
}

// SetLiveMigration sets the LiveMigration field in the Values.
func (n *noopETCD) SetLiveMigration(*LiveMigrationValues) {
}

// SetStaticPodControlPlaneNodesIPAddresses sets the IP addresses of all control plane nodes when etcd is run as
// static pod.
func (n *noopETCD) SetStaticPodControlPlaneNodesIPAddresses(...net.IP) {
}
