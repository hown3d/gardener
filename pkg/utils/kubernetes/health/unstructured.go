package health

import (
	"errors"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	kstatus "sigs.k8s.io/cli-utils/pkg/kstatus/status"
)

func CheckUnstructured(u *unstructured.Unstructured) error {
	result, err := kstatus.Compute(u)
	if err != nil {
		return err
	}
	switch result.Status {
	case kstatus.CurrentStatus:
		return nil
	default:
		return errors.New(result.Message)
	}
}
