package admission

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"

	a3yinformers "github.com/apoxy-dev/apoxy/client/informers"
	"github.com/apoxy-dev/apoxy/client/versioned/fake"
)

// testPlugin is a mock admission plugin that implements WantsApoxyInformerFactory.
type testPlugin struct {
	*admission.Handler
	informers a3yinformers.SharedInformerFactory
}

var _ admission.ValidationInterface = &testPlugin{}
var _ WantsApoxyInformerFactory = &testPlugin{}

func (p *testPlugin) SetApoxyInformerFactory(f a3yinformers.SharedInformerFactory) {
	p.informers = f
}

func (p *testPlugin) ValidateInitialization() error {
	if p.informers == nil {
		return fmt.Errorf("missing apoxy informer factory")
	}
	return nil
}

func (p *testPlugin) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	return nil
}

// plainPlugin is a mock admission plugin that does NOT implement
// WantsApoxyInformerFactory.
type plainPlugin struct {
	*admission.Handler
}

var _ admission.ValidationInterface = &plainPlugin{}

func (p *plainPlugin) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	return nil
}

func (p *plainPlugin) ValidateInitialization() error {
	return nil
}

func TestInitializerInjectsInformerFactory(t *testing.T) {
	client := fake.NewSimpleClientset()
	factory := a3yinformers.NewSharedInformerFactory(client, 0)
	initializer := New(factory, client)

	plugin := &testPlugin{Handler: admission.NewHandler(admission.Create)}
	initializer.Initialize(plugin)

	assert.Equal(t, factory, plugin.informers)
	require.NoError(t, plugin.ValidateInitialization())
}

func TestInitializerSkipsNonWanting(t *testing.T) {
	client := fake.NewSimpleClientset()
	factory := a3yinformers.NewSharedInformerFactory(client, 0)
	initializer := New(factory, client)

	plugin := &plainPlugin{Handler: admission.NewHandler(admission.Create)}

	// Must not panic.
	initializer.Initialize(plugin)
	require.NoError(t, plugin.ValidateInitialization())
}

func TestUninitializedPluginFails(t *testing.T) {
	plugin := &testPlugin{Handler: admission.NewHandler(admission.Create)}
	require.Error(t, plugin.ValidateInitialization())
}

func TestPluginRegistration(t *testing.T) {
	plugins := admission.NewPlugins()

	factory := func(config io.Reader) (admission.Interface, error) {
		return &testPlugin{Handler: admission.NewHandler(admission.Create)}, nil
	}
	plugins.Register("TestPlugin", factory)

	registered := plugins.Registered()
	assert.Contains(t, registered, "TestPlugin")
}

func TestPluginFactoryAndInitialize(t *testing.T) {
	// Simulate the flow that happens at apiserver startup:
	// 1. Plugin factory creates the plugin
	// 2. Initializer injects the informer factory
	// 3. Plugin passes ValidateInitialization

	factory := func(config io.Reader) (admission.Interface, error) {
		return &testPlugin{Handler: admission.NewHandler(admission.Create, admission.Update)}, nil
	}

	plugin, err := factory(nil)
	require.NoError(t, err)

	// Before initialization, ValidateInitialization should fail.
	tp := plugin.(*testPlugin)
	require.Error(t, tp.ValidateInitialization())

	// Initialize with our custom initializer.
	client := fake.NewSimpleClientset()
	informerFactory := a3yinformers.NewSharedInformerFactory(client, 0)
	initializer := New(informerFactory, client)
	initializer.Initialize(plugin)

	// After initialization, ValidateInitialization should pass.
	require.NoError(t, tp.ValidateInitialization())
	assert.Equal(t, informerFactory, tp.informers)

	// Plugin should handle the registered operations.
	assert.True(t, plugin.Handles(admission.Create))
	assert.True(t, plugin.Handles(admission.Update))
	assert.False(t, plugin.Handles(admission.Delete))

	// Call Validate and verify no error.
	attrs := admission.NewAttributesRecord(
		nil,                                               // object
		nil,                                               // old object
		schema.GroupVersionKind{},                          // kind
		"default",                                         // namespace
		"test",                                            // name
		schema.GroupVersionResource{Resource: "backends"},  // resource
		"",                                                // subresource
		admission.Create,                                  // operation
		&runtime.Unknown{},                                // operationOptions
		false,                                             // dryRun
		nil,                                               // userInfo
	)
	require.NoError(t, tp.Validate(context.Background(), attrs, nil))
}
