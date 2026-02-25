package admission

import (
	"k8s.io/apiserver/pkg/admission"

	a3yinformers "github.com/apoxy-dev/apoxy/client/informers"
)

// WantsApoxyInformerFactory defines an interface for admission plugins
// that need access to the Apoxy SharedInformerFactory for cross-resource
// validation and mutation.
type WantsApoxyInformerFactory interface {
	SetApoxyInformerFactory(a3yinformers.SharedInformerFactory)
	admission.InitializationValidator
}

type pluginInitializer struct {
	informers a3yinformers.SharedInformerFactory
}

var _ admission.PluginInitializer = &pluginInitializer{}

// New returns a new admission.PluginInitializer that injects the Apoxy
// SharedInformerFactory into plugins implementing WantsApoxyInformerFactory.
func New(informers a3yinformers.SharedInformerFactory) admission.PluginInitializer {
	return &pluginInitializer{informers: informers}
}

func (i *pluginInitializer) Initialize(plugin admission.Interface) {
	if wants, ok := plugin.(WantsApoxyInformerFactory); ok {
		wants.SetApoxyInformerFactory(i.informers)
	}
}
