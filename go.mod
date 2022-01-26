module github.com/klexhub/k8s-letsencrypt-force-renew

go 1.13

require (
	github.com/jetstack/cert-manager v0.13.1
	k8s.io/api v0.17.0
	k8s.io/apimachinery v0.17.0
	k8s.io/client-go v0.17.0
	sigs.k8s.io/controller-runtime v0.3.1-0.20191022174215-ad57a976ffa1
)
