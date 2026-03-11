// Package apiregistration handles Apoxy API service registration with Kubernetes API Aggregation
package apiregistration

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	apiregistrationclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

// APIRegistration handles registration of Apoxy APIs with Kubernetes API Aggregation
type APIRegistration struct {
	apiRegC apiregistrationclient.Interface
}

// NewAPIRegistration creates a new APIRegistration with the given client-go config
func NewAPIRegistration(config *rest.Config) (*APIRegistration, error) {
	apiRegC, err := apiregistrationclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create api registration client: %w", err)
	}

	return &APIRegistration{
		apiRegC: apiRegC,
	}, nil
}

// RegisterAPIServices registers all Apoxy API services with Kubernetes API Aggregation
func (a *APIRegistration) RegisterAPIServices(ctx context.Context, serviceName, namespace string, port int, caBundle []byte) error {
	log.Infof("setting up API Aggregation")
	desired := make(map[string]struct{}, len(AllAPIServices))
	for _, apiSvcDef := range AllAPIServices {
		svc := apiSvcDef.ToAPIService(serviceName, namespace, port, caBundle)
		desired[svc.Name] = struct{}{}
		if _, err := a.apiRegC.ApiregistrationV1().APIServices().Create(ctx, svc, metav1.CreateOptions{}); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return err
			}
			if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				curSvc, err := a.apiRegC.ApiregistrationV1().APIServices().Get(ctx, svc.Name, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to get existing APIService %s: %w", svc.Name, err)
				}
				nextSvc := svc.DeepCopy()
				nextSvc.ResourceVersion = curSvc.ResourceVersion
				_, err = a.apiRegC.ApiregistrationV1().APIServices().Update(ctx, nextSvc, metav1.UpdateOptions{})
				return err
			}); err != nil {
				return fmt.Errorf("failed to update APIService %s: %w", svc.Name, err)
			}
		}
		log.Infof("Registered API service: %s", svc.Name)
	}

	apiServices, err := a.apiRegC.ApiregistrationV1().APIServices().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list API services: %w", err)
	}
	for _, existing := range apiServices.Items {
		if existing.Spec.Service == nil {
			continue
		}
		if existing.Spec.Service.Name != serviceName || existing.Spec.Service.Namespace != namespace {
			continue
		}
		if !strings.HasSuffix(existing.Spec.Group, ".apoxy.dev") {
			continue
		}
		if _, ok := desired[existing.Name]; ok {
			continue
		}
		if err := a.apiRegC.ApiregistrationV1().APIServices().Delete(ctx, existing.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete stale APIService %s: %w", existing.Name, err)
		}
		log.Infof("Deleted stale API service: %s", existing.Name)
	}
	return nil
}
