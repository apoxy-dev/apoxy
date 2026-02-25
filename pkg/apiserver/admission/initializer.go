package admission

import (
	"k8s.io/apiserver/pkg/admission"

	a3yinformers "github.com/apoxy-dev/apoxy/client/informers"
	a3yclient "github.com/apoxy-dev/apoxy/client/versioned"
)

// WantsApoxyInformerFactory defines an interface for admission plugins
// that need access to the Apoxy SharedInformerFactory for cross-resource
// validation and mutation.
type WantsApoxyInformerFactory interface {
	SetApoxyInformerFactory(a3yinformers.SharedInformerFactory)
	admission.InitializationValidator
}

// WantsApoxyClient defines an interface for admission plugins that need
// a typed Apoxy client to read or write resources during admission.
type WantsApoxyClient interface {
	SetApoxyClient(a3yclient.Interface)
	admission.InitializationValidator
}

type pluginInitializer struct {
	informers a3yinformers.SharedInformerFactory
	client    a3yclient.Interface
}

var _ admission.PluginInitializer = &pluginInitializer{}

// New returns a new admission.PluginInitializer that injects the Apoxy
// SharedInformerFactory and client into plugins implementing the
// corresponding Wants* interfaces.
func New(informers a3yinformers.SharedInformerFactory, client a3yclient.Interface) admission.PluginInitializer {
	return &pluginInitializer{informers: informers, client: client}
}

func (i *pluginInitializer) Initialize(plugin admission.Interface) {
	if wants, ok := plugin.(WantsApoxyInformerFactory); ok {
		wants.SetApoxyInformerFactory(i.informers)
	}
	if wants, ok := plugin.(WantsApoxyClient); ok {
		wants.SetApoxyClient(i.client)
	}
}
