package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
)

const (
	kubescapeGroupVersion = "spdx.softwarecomposition.kubescape.io/v1beta1"
	sbomSyftResource      = "sbomsyfts"
)

// WaitForKubescapeAPI blocks until the kubescape storage API serves sbomsyfts, polling discovery
// every interval, or until ctx is cancelled.
func WaitForKubescapeAPI(ctx context.Context, cfg *rest.Config, interval time.Duration, log logr.Logger) error {
	disc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return fmt.Errorf("creating discovery client: %w", err)
	}
	return waitForKubescapeAPIWith(ctx, disc, interval, log)
}

func waitForKubescapeAPIWith(ctx context.Context, disc discovery.DiscoveryInterface, interval time.Duration, log logr.Logger) error {
	for {
		if kubescapeAPIPresent(disc) {
			return nil
		}
		log.Info(fmt.Sprintf("kubescape storage API not found, retrying in %.0fs", interval.Seconds()), "groupVersion", kubescapeGroupVersion)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func kubescapeAPIPresent(disc discovery.DiscoveryInterface) bool {
	list, err := disc.ServerResourcesForGroupVersion(kubescapeGroupVersion)
	if err != nil || list == nil {
		return false
	}
	for _, r := range list.APIResources {
		if r.Name == sbomSyftResource {
			return true
		}
	}
	return false
}
