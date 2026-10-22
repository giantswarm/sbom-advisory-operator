package main

import (
	"crypto/tls"
	"flag"
	"os"
	"time"

	kubescapev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/giantswarm/sbom-advisory-operator/api/wgpolicyk8s.io/v1alpha2"
	"github.com/giantswarm/sbom-advisory-operator/internal/controller"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(kubescapev1beta1.AddToScheme(scheme))
	utilruntime.Must(v1alpha2.AddToScheme(scheme))
}

// watchListSemanticsDisabledListerWatcherWrapper tells client-go not to use WatchList streaming.
// kubescape storage accepts a watch-list request and then never sends the initial events, so an
// informer using the protocol never syncs (kubescape/storage#320). Classic list+watch is used for
// every informer; the other watched kinds lose nothing by it.
type watchListSemanticsDisabledListerWatcherWrapper struct {
	toolscache.ListerWatcher
}

func (w watchListSemanticsDisabledListerWatcherWrapper) IsWatchListSemanticsUnSupported() bool {
	return true
}

// cacheOptions bounds what the manager caches: ConfigMaps only in the advisory namespace (so a
// namespaced Role suffices). PolicyReports are deliberately absent: a ByObject entry is resolved
// through the RESTMapper when the manager is created and would fail on a cluster without the
// PolicyReport CRD; the controller watches them as metadata only instead and reads bodies
// uncached. The WatchList opt-out applies to every informer.
func cacheOptions(advisoriesNamespace string) cache.Options {
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.ConfigMap{}: {Namespaces: map[string]cache.Config{advisoriesNamespace: {}}},
		},
		NewInformer: func(lw toolscache.ListerWatcher, obj runtime.Object, resync time.Duration, indexers toolscache.Indexers) toolscache.SharedIndexInformer {
			return toolscache.NewSharedIndexInformer(watchListSemanticsDisabledListerWatcherWrapper{lw}, obj, resync, indexers)
		},
	}
}

func main() {
	var metricsAddr string
	var probeAddr string
	var enableLeaderElection bool
	var secureMetrics bool
	var enableHTTP2 bool
	var discoveryInterval time.Duration
	var advisoriesNamespace, advisoriesName, advisoriesKey string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", false, "If set the metrics endpoint is served securely.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false, "If set, HTTP/2 will be enabled for the metrics server.")
	flag.DurationVar(&discoveryInterval, "kubescape-discovery-interval", 60*time.Second, "How often to look for the kubescape storage API while it is absent.")
	flag.StringVar(&advisoriesNamespace, "advisories-configmap-namespace", os.Getenv("POD_NAMESPACE"), "Namespace of the advisory ConfigMap (defaults to $POD_NAMESPACE).")
	flag.StringVar(&advisoriesName, "advisories-configmap-name", "sbom-advisory-operator-advisories", "Name of the advisory ConfigMap.")
	flag.StringVar(&advisoriesKey, "advisories-configmap-key", "advisories.yaml", "Key of the advisory ConfigMap holding the advisories YAML.")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// HTTP/2 stays off unless asked for, to avoid the Rapid Reset class of issues
	// (GHSA-qppj-fm5r-hxr3, GHSA-4374-p667-p6c8).
	tlsOpts := []func(*tls.Config){}
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} })
	}

	cfg := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:   metricsAddr,
			SecureServing: secureMetrics,
			TLSOpts:       tlsOpts,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "sbom-advisory-operator.giantswarm.io",
		Cache:                  cacheOptions(advisoriesNamespace),
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()

	source := controller.NewAdvisorySource(advisoriesNamespace, advisoriesName, advisoriesKey, mgr.GetEventRecorder("sbom-advisory-operator"))
	reconciler := &controller.SBOMSyftReconciler{
		Client:     mgr.GetClient(),
		Reader:     mgr.GetAPIReader(),
		Advisories: source.Current,
		Now:        metav1.Now,
		Source:     source,
	}

	// The controller is registered only once the kubescape storage API exists, so the pod stays
	// healthy on clusters without kubescape instead of crashlooping.
	go func() {
		if err := controller.WaitForKubescapeAPI(ctx, cfg, discoveryInterval, setupLog); err != nil {
			return
		}
		if err := reconciler.SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "sbomsyft")
			os.Exit(1)
		}
		setupLog.Info("sbomsyft controller registered")
	}()

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
