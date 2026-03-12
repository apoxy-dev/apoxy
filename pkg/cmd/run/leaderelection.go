package run

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

const defaultRuntimeNamespace = "apoxy"

func runtimeNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	return defaultRuntimeNamespace
}

func withLeaderElection(opts ctrl.Options, component, namespace, clusterName string) ctrl.Options {
	opts.LeaderElection = true
	opts.LeaderElectionNamespace = namespace
	opts.LeaderElectionReleaseOnCancel = true
	opts.LeaderElectionID = leaderElectionID(component, namespace, clusterName)
	// Runtime components don't need Kubernetes Events for correctness. Disabling
	// event emission keeps leader election from spamming logs or requiring extra
	// RBAC just to report "became leader" messages.
	opts.EventBroadcaster = noopEventBroadcaster{}
	return opts
}

func leaderElectionID(component, namespace, clusterName string) string {
	base := strings.Join([]string{component, namespace, clusterName}, "/")
	sum := sha256.Sum256([]byte(base))
	return fmt.Sprintf("%s.%s.apoxy.dev", component, hex.EncodeToString(sum[:6]))
}

type noopEventBroadcaster struct{}

func (noopEventBroadcaster) StartEventWatcher(func(*corev1.Event)) watch.Interface {
	return watch.NewEmptyWatch()
}

func (noopEventBroadcaster) StartRecordingToSink(record.EventSink) watch.Interface {
	return watch.NewEmptyWatch()
}

func (noopEventBroadcaster) StartLogging(func(string, ...interface{})) watch.Interface {
	return watch.NewEmptyWatch()
}

func (noopEventBroadcaster) StartStructuredLogging(klog.Level) watch.Interface {
	return watch.NewEmptyWatch()
}

func (noopEventBroadcaster) NewRecorder(*runtime.Scheme, corev1.EventSource) record.EventRecorderLogger {
	return noopEventRecorder{}
}

func (noopEventBroadcaster) Shutdown() {}

type noopEventRecorder struct{}

func (noopEventRecorder) Event(runtime.Object, string, string, string) {}

func (noopEventRecorder) Eventf(runtime.Object, string, string, string, ...interface{}) {}

func (noopEventRecorder) AnnotatedEventf(runtime.Object, map[string]string, string, string, string, ...interface{}) {
}

func (r noopEventRecorder) WithLogger(klog.Logger) record.EventRecorderLogger {
	return r
}
