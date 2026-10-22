package controller

import (
	"context"
	"fmt"

	kubescapev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/giantswarm/sbom-advisory-operator/api/wgpolicyk8s.io/v1alpha2"
	"github.com/giantswarm/sbom-advisory-operator/internal/advisory"
)

// SBOMSyftReconciler turns one SBOMSyft into one PolicyReport.
type SBOMSyftReconciler struct {
	client.Client
	// Reader fetches full SBOMSyft bodies; it must bypass the cache, which only holds metadata.
	Reader client.Reader
	// Advisories returns the advisory set to evaluate against.
	Advisories func() *advisory.Set
	// Now stamps results.
	Now func() metav1.Time
	// Source, when set, is reloaded from its ConfigMap and every SBOMSyft is re-queued on change.
	Source *AdvisorySource
}

// Reconcile evaluates the SBOMSyft named by req and upserts or deletes its PolicyReport.
func (r *SBOMSyftReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	sbom := &kubescapev1beta1.SBOMSyft{}
	if err := r.Reader.Get(ctx, req.NamespacedName, sbom); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, r.deleteReport(ctx, req)
		}
		return ctrl.Result{}, fmt.Errorf("reading SBOMSyft %s: %w", req.NamespacedName, err)
	}

	if status, unavailable := SBOMUnavailable(sbom); unavailable {
		logger.V(1).Info("SBOM not evaluable", "status", status)
		return ctrl.Result{}, r.upsertReport(ctx, BuildUnavailablePolicyReport(sbom, status, r.Now()))
	}

	results := r.Advisories().Evaluate(InputFromSBOM(sbom))
	if len(results) == 0 {
		return ctrl.Result{}, r.deleteReport(ctx, req)
	}
	return ctrl.Result{}, r.upsertReport(ctx, BuildPolicyReport(sbom, results, r.Now()))
}

func (r *SBOMSyftReconciler) upsertReport(ctx context.Context, desired *v1alpha2.PolicyReport) error {
	existing := &v1alpha2.PolicyReport{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("creating PolicyReport %s: %w", client.ObjectKeyFromObject(desired), err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading PolicyReport %s: %w", client.ObjectKeyFromObject(desired), err)
	}
	if reportUnchanged(existing, desired) {
		return nil
	}
	desired.ResourceVersion = existing.ResourceVersion
	if err := r.Update(ctx, desired); err != nil {
		return fmt.Errorf("updating PolicyReport %s: %w", client.ObjectKeyFromObject(desired), err)
	}
	return nil
}

// reportUnchanged is true when the only difference between the stored and the desired report is
// the result timestamp; rewriting such a report would only churn the API server and re-trigger
// the owner watch.
func reportUnchanged(existing, desired *v1alpha2.PolicyReport) bool {
	if !equality.Semantic.DeepEqual(existing.Labels, desired.Labels) ||
		!equality.Semantic.DeepEqual(existing.OwnerReferences, desired.OwnerReferences) ||
		!equality.Semantic.DeepEqual(existing.Scope, desired.Scope) ||
		existing.Summary != desired.Summary ||
		len(existing.Results) != len(desired.Results) {
		return false
	}
	for i := range desired.Results {
		a, b := existing.Results[i], desired.Results[i]
		a.Timestamp, b.Timestamp = metav1.Timestamp{}, metav1.Timestamp{}
		if !equality.Semantic.DeepEqual(a, b) {
			return false
		}
	}
	return true
}

func (r *SBOMSyftReconciler) deleteReport(ctx context.Context, req ctrl.Request) error {
	pr := &v1alpha2.PolicyReport{}
	pr.Name, pr.Namespace = req.Name, req.Namespace
	if err := r.Delete(ctx, pr); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("deleting PolicyReport %s: %w", req.NamespacedName, err)
	}
	return nil
}

// enqueueAllSBOMs reloads the advisory ConfigMap and returns a request for every SBOMSyft, so a
// changed advisory set is applied everywhere. ConfigMaps other than the configured one are ignored.
func (r *SBOMSyftReconciler) enqueueAllSBOMs(ctx context.Context, obj client.Object) []reconcile.Request {
	if r.Source == nil || !r.Source.Matches(obj.GetNamespace(), obj.GetName()) {
		return nil
	}
	logger := log.FromContext(ctx)
	cm := &corev1.ConfigMap{}
	switch err := r.Get(ctx, client.ObjectKeyFromObject(obj), cm); {
	case apierrors.IsNotFound(err):
		r.Source.Reset()
	case err != nil:
		logger.Error(err, "reading advisory ConfigMap")
		return nil
	default:
		if err := r.Source.Load(cm); err != nil {
			logger.Error(err, "advisory ConfigMap rejected, keeping the previous set")
		}
	}

	list := &metav1.PartialObjectMetadataList{}
	list.SetGroupVersionKind(kubescapev1beta1.SchemeGroupVersion.WithKind("SBOMSyftList"))
	if err := r.List(ctx, list); err != nil {
		logger.Error(err, "listing SBOMSyft metadata")
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(list.Items))
	for _, item := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&item)})
	}
	return reqs
}

// SetupWithManager registers the controller: SBOMSyft is watched as metadata only so the cache
// never holds SBOM bodies, and the advisory ConfigMap re-queues everything on change.
func (r *SBOMSyftReconciler) SetupWithManager(mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr).
		Named("sbomsyft").
		For(&kubescapev1beta1.SBOMSyft{}, builder.OnlyMetadata).
		Owns(&v1alpha2.PolicyReport{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 2})
	if r.Source != nil {
		b = b.Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.enqueueAllSBOMs),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return r.Source.Matches(obj.GetNamespace(), obj.GetName())
			})))
	}
	return b.Complete(r)
}
