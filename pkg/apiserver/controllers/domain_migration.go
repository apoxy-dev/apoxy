package controllers

import (
	"context"
	"fmt"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1alpha3 "github.com/apoxy-dev/apoxy/api/core/v1alpha3"
	a3yclient "github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/admission"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

// MigrateDomainsToDomainRecords lists all existing Domains and creates
// reflected DomainRecords for each. This is a one-time idempotent migration
// that should be called after the apiserver is ready but before controllers
// start.
func MigrateDomainsToDomainRecords(ctx context.Context, client a3yclient.Interface) error {
	domainClient := client.CoreV1alpha3().Domains()
	drClient := client.CoreV1alpha3().DomainRecords()

	domains, err := domainClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing domains for migration: %w", err)
	}

	if len(domains.Items) == 0 {
		log.Infof("No existing Domains to migrate")
		return nil
	}

	log.Infof("Migrating %d Domain(s) to DomainRecords", len(domains.Items))

	for i := range domains.Items {
		domain := &domains.Items[i]

		// Skip reflected Domains (created by the reverse path).
		if ann := domain.GetAnnotations(); ann != nil && ann[admission.ReflectedAnnotation] == "true" {
			continue
		}

		records := admission.DomainToDomainRecords(domain)
		for j := range records {
			r := &records[j]
			existing, err := drClient.Get(ctx, r.Name, metav1.GetOptions{})
			if err == nil {
				// Already exists — update if needed.
				if !specMatchesMigration(existing, r) {
					existing.Spec = r.Spec
					existing.Annotations = r.Annotations
					if _, err := drClient.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
						log.Errorf("Failed to update migrated DomainRecord %s: %v", r.Name, err)
					} else {
						log.Infof("Updated migrated DomainRecord %s for Domain %s", r.Name, domain.Name)
					}
				}
				continue
			}
			if !kerrors.IsNotFound(err) {
				log.Errorf("Failed to check DomainRecord %s: %v", r.Name, err)
				continue
			}
			if _, err := drClient.Create(ctx, r, metav1.CreateOptions{}); err != nil {
				if kerrors.IsAlreadyExists(err) {
					continue
				}
				log.Errorf("Failed to create migrated DomainRecord %s: %v", r.Name, err)
			} else {
				log.Infof("Created migrated DomainRecord %s for Domain %s", r.Name, domain.Name)
			}
		}
	}

	log.Infof("Domain to DomainRecord migration complete")
	return nil
}

// specMatchesMigration is a lightweight check used during migration.
func specMatchesMigration(existing *corev1alpha3.DomainRecord, desired *corev1alpha3.DomainRecord) bool {
	// Check reflected annotation.
	existingAnn := existing.GetAnnotations()
	if existingAnn == nil || existingAnn[admission.ReflectedAnnotation] != "true" {
		return false
	}
	// Compare zone and name.
	return existing.Spec.Zone == desired.Spec.Zone && existing.Spec.Name == desired.Spec.Name
}
