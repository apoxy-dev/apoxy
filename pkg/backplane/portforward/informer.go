// Package portforward watches a port on a ProxyReplica and forwards from
// a local port to the remote port on the ProxyReplica.
package portforward

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	adminv3 "github.com/envoyproxy/go-control-plane/envoy/admin/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/encoding/protojson"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/apoxy-dev/apoxy/client/informers"
	"github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/pkg/drivers"
	"github.com/apoxy-dev/apoxy/pkg/log"

	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy/api/controllers/v1alpha1"
)

const (
	resyncPeriod = 10 * time.Second

	adminPort = 19000
)

// PortForwarder forwards a local port to a remote port.
type PortForwarder struct {
	proxyName   string
	replicaName string
	cname       string

	factory  informers.SharedInformerFactory
	informer cache.SharedIndexInformer
	wq       workqueue.RateLimitingInterface
	// portStopCh is a map of ports to the corresponding subroutines' stop channels.
	portStopCh map[string]chan struct{}
}

// NewPortForwarder creates a new PortForwarder.
// proxyName specifies a Proxy to watch and cname is the container to forward to.
// The local port is the same as the remote port if available.
func NewPortForwarder(rc *rest.Config, proxyName, replicaName, cname string) (*PortForwarder, error) {
	c, err := versioned.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("could not create client: %v", err)
	}
	return &PortForwarder{
		proxyName:   proxyName,
		replicaName: replicaName,
		cname:       cname,
		factory: informers.NewSharedInformerFactoryWithOptions(
			c,
			resyncPeriod,
			informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
				opts.FieldSelector = "metadata.name=" + proxyName
			}),
		),
		wq:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "portforward"),
		portStopCh: make(map[string]chan struct{}),
	}, nil
}

func findReplicaStatus(p *ctrlv1alpha1.Proxy, rname string) (*ctrlv1alpha1.ProxyReplicaStatus, bool) {
	for i := range p.Status.Replicas {
		if p.Status.Replicas[i].Name == rname {
			return p.Status.Replicas[i], true
		}
	}
	return nil, false
}

func (pf *PortForwarder) doForward(protocol gwapiv1.ProtocolType, port uint32) error {
	log.Infof("Forwarding %s/%d", protocol, port)
	pname := fmt.Sprintf("%s/%d", protocol, port)
	if _, ok := pf.portStopCh[pname]; !ok {
		stopCh := make(chan struct{})
		switch protocol {
		case gwapiv1.TCPProtocolType, gwapiv1.HTTPProtocolType, gwapiv1.HTTPSProtocolType:
			fmt.Printf("Listening on %s\n", pname)
			go drivers.ForwardTCP(stopCh, pf.cname, int(port), int(port))
		default:
			return fmt.Errorf("invalid protocol %q", protocol)
		}

		pf.portStopCh[pname] = stopCh
	}
	return nil
}

func (pf *PortForwarder) sync(key string) error {
	obj, exists, err := pf.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("could not get object by key %q: %v", key, err)
	}

	proxy := obj.(*ctrlv1alpha1.Proxy)
	if !exists {
		for p, stopCh := range pf.portStopCh {
			delete(pf.portStopCh, p)
			close(stopCh)
			fmt.Printf("Stopped listening on :%s\n", p)
		}
		return nil
	}

	rs, ok := findReplicaStatus(proxy, pf.replicaName)
	if !ok {
		log.Infof("replica %q not found in proxy %q", pf.replicaName, pf.proxyName)
		return nil
	}
	if rs.Phase != ctrlv1alpha1.ProxyReplicaPhaseRunning {
		log.Infof("replica %q is not running: %v", pf.replicaName, rs.Phase)
		return nil
	}

	log.Infof("Setting up port forwarding...")

	// Forward the admin port first.
	if err := pf.doForward(gwapiv1.TCPProtocolType, adminPort); err != nil {
		return err
	}

	// Now use the admin port to pull other listeners to forward.
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/listeners?format=json", adminPort))
	if err != nil {
		return fmt.Errorf("failed to get listeners from admin endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	adminListeners := adminv3.Listeners{}
	if err := protojson.Unmarshal(body, &adminListeners); err != nil {
		return fmt.Errorf("failed to unmarshal listeners: %w", err)
	}

	envoyProto2GW := map[corev3.SocketAddress_Protocol]gwapiv1.ProtocolType{
		corev3.SocketAddress_TCP: gwapiv1.TCPProtocolType,
		corev3.SocketAddress_UDP: gwapiv1.UDPProtocolType,
	}
	wantForwarded := sets.New[string]()
	for _, ls := range adminListeners.ListenerStatuses {
		if ls.LocalAddress == nil || ls.LocalAddress.GetSocketAddress() == nil {
			log.Infof("skipping listener with nil address")
			continue
		}
		sa := ls.LocalAddress.GetSocketAddress()
		if _, ok := envoyProto2GW[sa.GetProtocol()]; !ok {
			log.Infof("skipping listener with unsupported protocol %q", sa.GetProtocol())
			continue
		}
		if err := pf.doForward(envoyProto2GW[sa.GetProtocol()], sa.GetPortValue()); err != nil {
			log.Errorf("failed to forward %s/%d: %w", sa.GetProtocol(), sa.GetPortValue(), err)
			continue
		}

		wantForwarded.Insert(fmt.Sprintf("%s/%d", sa.GetProtocol(), sa.GetPortValue()))
	}

	for pname, stopCh := range pf.portStopCh {
		if pname == "TCP/19000" { // Always keep the admin port.
			continue
		}
		if !wantForwarded.Has(pname) {
			delete(pf.portStopCh, pname)
			close(stopCh)
			fmt.Printf("Stopped listening on %s\n", pname)
		}
	}

	return nil
}

func (pf *PortForwarder) processNextWorkItem() bool {
	key, quit := pf.wq.Get()
	if quit {
		return false
	}
	defer pf.wq.Done(key)

	err := pf.sync(key.(string))
	if err != nil {
		log.Errorf("Sync %q failed with: %v", key, err)
		pf.wq.AddRateLimited(key)
		return true
	}

	pf.wq.Forget(key)
	return true
}

func (pf *PortForwarder) runWorker() {
	for pf.processNextWorkItem() {
	}
}

// Run runs a port forwarder watch loop.
func (pf *PortForwarder) Run(
	ctx context.Context,
) error {
	pf.informer = pf.factory.Controllers().V1alpha1().Proxies().Informer()
	pf.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			log.Debugf("Add %v", obj)
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err != nil {
				log.Errorf("could not get key for added object: %v", err)
			}
			pf.wq.Add(key)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			log.Debugf("Update %v", newObj)
			key, err := cache.MetaNamespaceKeyFunc(newObj)
			if err != nil {
				log.Errorf("could not get key for updated object: %v", err)
				return
			}
			pf.wq.Add(key)
		},
		DeleteFunc: func(obj interface{}) {
			log.Debugf("Delete %v", obj)
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err != nil {
				log.Errorf("could not get key for deleted object: %v", err)
			}
			pf.wq.Add(key)
		},
	})

	stopCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		}
		close(stopCh)
	}()
	pf.factory.Start(stopCh) // Must be called after new informers are added.
	synced := pf.factory.WaitForCacheSync(ctx.Done())
	for v, s := range synced {
		if !s {
			return fmt.Errorf("informer %s failed to sync", v)
		}
	}

	// Run a single worker to not worry about concurrency. It should be fast
	// enough for our use case.
	go wait.Until(pf.runWorker, time.Second, stopCh)

	<-stopCh

	return nil
}
