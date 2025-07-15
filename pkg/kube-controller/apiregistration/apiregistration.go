// Package apiregistration handles Apoxy API service registration with Kubernetes API Aggregation
package apiregistration

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
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
	for _, apiSvcDef := range AllAPIServices {
		svc := apiSvcDef.ToAPIService(serviceName, namespace, port, caBundle)
		if _, err := a.apiRegC.ApiregistrationV1().APIServices().Create(ctx, svc, metav1.CreateOptions{}); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return err
			}
			curSvc, err := a.apiRegC.ApiregistrationV1().APIServices().Get(ctx, svc.Name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get existing APIService %s: %w", svc.Name, err)
			}
			svc.ResourceVersion = curSvc.ResourceVersion
			if _, err := a.apiRegC.ApiregistrationV1().APIServices().Update(ctx, svc, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("failed to update APIService %s: %w", svc.Name, err)
			}
		}
		log.Infof("Registered API service: %s", svc.Name)
	}
	return nil
}
