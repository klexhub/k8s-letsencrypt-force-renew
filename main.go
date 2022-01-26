package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jetstack/cert-manager/pkg/api"
	capi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

var (
	issuerName string
	renew      bool
)

func init() {
	flag.StringVar(&issuerName, "issuerName", "", "Filter affected certs by issuer name")
	flag.BoolVar(&renew, "renew", false, "If true, any affected certificates will be renewed. This may take a few minutes per Certificate.")
}

func main() {
	flag.Parse()

	if issuerName != "" {
		log.Printf("!!!!! --issuerName has been set. Filter onyl certs with issues by: %s !!!!!", issuerName)

	}
	if renew {
		log.Printf("!!!!! --renew has been set to TRUE. Any affected certificates will have a renewal automatically triggered if found !!!!!")
		log.Printf("!!!!! Waiting 5s before proceeding, if you DO NOT renewals to be triggered, hit ctrl+c NOW !!!!!")
		time.Sleep(time.Second * 5)
	}
	log.Println("This tool will query a Kubernetes cluster, check if any " +
		"certificates are issued with cert-manager " +
		"and trigger a renewal of any affected certificates. " +
		"It is not safe to run multiple times, it will trigger a renewal every time.")

	if err := run(); err != nil {
		log.Printf("%v", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	// Build an API client
	cfg := ctrl.GetConfigOrDie()
	mapper, err := apiutil.NewDynamicRESTMapper(cfg)
	if err != nil {
		return err
	}
	cl, err := client.New(cfg, client.Options{
		Scheme: api.Scheme,
		Mapper: mapper,
	})
	if err != nil {
		return fmt.Errorf("error building API client: %w", err)
	}

	var certs capi.CertificateList
	if err := cl.List(ctx, &certs); err != nil {
		return fmt.Errorf("error listing Certificate resources: %w", err)
	}

	log.Printf("Found %d Certificate resources to check", len(certs.Items))
	var secrets core.SecretList
	if err := cl.List(ctx, &secrets); err != nil {
		return fmt.Errorf("error listing Secret resources: %w", err)
	}

	secretsMap := makeSecretsMap(secrets.Items)
	serialsToCertificates := make(map[string]capi.Certificate)

	skipped := 0
	for _, crt := range certs.Items {
		skip := false
		log.Printf("+++ Checking Secret resource for Certificate %s/%s", crt.Namespace, crt.Name)
		secret, ok := secretsMap[crt.Namespace+"/"+crt.Spec.SecretName]
		if !ok {
			log.Printf("Unable to find Secret resource %q, skipping...", crt.Spec.SecretName)
			skipped++
			continue
		}
		if secret.Data == nil || secret.Data[core.TLSCertKey] == nil {
			log.Printf("Secret %q does not contain any data for key %q, skipping...", crt.Spec.SecretName, core.TLSCertKey)
			skipped++
			continue
		}
		certPEM := secret.Data[core.TLSCertKey]
		cert, err := pki.DecodeX509CertificateBytes(certPEM)
		if err != nil {
			log.Printf("Failed to decode x509 certificate data in Secret %q: %v, skipping...", crt.Spec.SecretName, err)
			skipped++
			continue
		}

		//filter secrets by issuer name
		if issuerName != "" {
			for key, value := range secret.Annotations {
				if key == "cert-manager.io/issuer-name" {
					if value != issuerName {
						skip = true
						skipped++
						continue
					}
				}
			}
		}
		if !skip {
			serialsToCertificates[cert.SerialNumber.String()] = crt
		}
	}

	log.Println("Finished analyzing certificates, results:")
	log.Printf("  Skipped/unable to check: %d", skipped)
	log.Printf("  Affected certificates: %d", len(serialsToCertificates))

	if len(serialsToCertificates) == 0 {
		return nil
	}
	if !renew {
		log.Println()
		log.Printf("Will NOT trigger a renewal as --renew set to false")
		return nil
	}

	log.Println()
	log.Printf("Will now attempting to renew the following certificates:")
	for sn, cert := range serialsToCertificates {
		log.Printf("  * %s/%s (serial number: %s)", cert.Namespace, cert.Name, sn)
	}
	log.Println()
	log.Printf("!!!!! Will now attempt to renew %d certificates, waiting 2s... !!!!!", len(serialsToCertificates))
	time.Sleep(time.Second * 2)
	log.Println()

	for _, cert := range serialsToCertificates {
		log.Printf("Triggering renewal of Certificate %s/%s", cert.Namespace, cert.Name)
		if err := renewCertificate(ctx, cl, cert); err != nil {
			log.Printf("Failed to renew certificate %s/%s: %v", cert.Namespace, cert.Name, err)
			return err
		}
	}
	return nil
}

func renewCertificate(ctx context.Context, cl client.Client, cert capi.Certificate) error {
	var requests capi.CertificateRequestList
	if err := cl.List(ctx, &requests, client.InNamespace(cert.Namespace)); err != nil {
		return err
	}
	for _, req := range requests.Items {
		// If any existing CertificateRequest resources exist and are complete,
		// we delete them to avoid a re-issuance of the same certificate.
		if !metav1.IsControlledBy(&req, &cert) {
			continue
		}

		// This indicates an issuance is currently in progress
		if len(req.Status.Certificate) == 0 {
			log.Printf("Found existing CertificateRequest %s/%s for Certificate - skipping triggering a renewal...", req.Namespace, req.Name)
			return nil
		}

		if err := cl.Delete(ctx, &req); err != nil {
			log.Printf("Failed to delete old CertificateRequest %s/%s for Certificate", req.Namespace, req.Name)
			return err
		}

		log.Printf("Deleted old CertificateRequest %s/%s for Certificate", req.Namespace, req.Name)
	}

	// Fetch an up to date copy of the Secret resource for this Certificate
	var secret core.Secret
	if err := cl.Get(ctx, client.ObjectKey{Namespace: cert.Namespace, Name: cert.Spec.SecretName}, &secret); err != nil {
		log.Printf("Failed to retrieve up-to-date copy of existing Secret resource for Certificate: %v", err)
		return err
	}

	// Manually override/set the IssuerNameAnnotationKey - this will cause cert-manager
	// to assume that we have changed the 'issuerRef' specified on the Certificate and
	// trigger a one-time renewal.
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations[capi.IssuerNameAnnotationKey] = "force-renewal-triggered"
	if err := cl.Update(ctx, &secret); err != nil {
		log.Printf("Failed to update Secret resource for Certificate: %v", err)
		return err
	}

	log.Printf("Triggered renewal of Certificate - waiting for new CertificateRequest resource to be created...")
	// Wait for a CertificateRequest resource to be created
	err := wait.Poll(time.Second, time.Minute, func() (bool, error) {
		var requests capi.CertificateRequestList
		if err := cl.List(ctx, &requests, client.InNamespace(cert.Namespace)); err != nil {
			return false, err
		}
		// Wait for a CertificateRequest owned by this Certificate to exist
		for _, req := range requests.Items {
			if metav1.IsControlledBy(&req, &cert) {
				log.Printf("CertificateRequest %s/%s found, renewal in progress!", req.Namespace, req.Name)
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		log.Printf("Failed to wait for new CertificateRequest to be created: %v", err)
		return err
	}
	return nil
}

func makeSecretsMap(secrets []core.Secret) map[string]core.Secret {
	m := make(map[string]core.Secret)
	for _, s := range secrets {
		m[s.Namespace+"/"+s.Name] = s
	}
	return m
}
