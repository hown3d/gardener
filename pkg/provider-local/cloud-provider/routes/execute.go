package routes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"k8s.io/client-go/util/exec"
	"k8s.io/klog/v2"
)

type executor interface {
	Execute(ctx context.Context, name string, cmd []string) (stdout io.Reader, stderr io.Reader, err error)
}

func NewPodExecutor(namespace string, pe kubernetes.PodExecutor) executor {
	return &podExecutor{
		pe:        pe,
		namespace: namespace,
	}
}

var _ executor = (*podExecutor)(nil)

type podExecutor struct {
	pe        kubernetes.PodExecutor
	namespace string
}

// Execute implements [executor].
func (p *podExecutor) Execute(ctx context.Context, name string, cmd []string) (stdout io.Reader, stderr io.Reader, err error) {
	klog.V(1).Infof("running command %v on pod %s", cmd, name)
	stdout, stderr, err = p.pe.Execute(ctx, p.namespace, name, "", cmd...)
	if err != nil {
		if exitErr, ok := errors.AsType[exec.CodeExitError](err); ok && exitErr.Exited() {
			return nil, nil, processError{code: exitErr.Code, stderr: stderr, stdout: stdout}
		}
		return nil, nil, err
	}
	return stdout, stderr, nil
}

func NewContainerExecutor(dockerClient dockerclient.APIClient) executor {
	return &containerExecutor{
		DockerClient: dockerClient,
	}
}

type containerExecutor struct {
	// DockerClient is the client connected to the host's Docker socket.
	DockerClient dockerclient.APIClient
}

// Execute implements [executor].
func (p *containerExecutor) Execute(ctx context.Context, name string, cmd []string) (io.Reader, io.Reader, error) {
	containerID, err := p.containerIDByName(ctx, name)
	if err != nil {
		return nil, nil, err
	}
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

func (p *containerExecutor) containerIDByName(ctx context.Context, name string) (string, error) {
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
