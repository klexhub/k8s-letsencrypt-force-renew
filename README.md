# k8s-letsencrypt-force-renew

This tool will check all cert-manager Certificate resources installed in your
cluster and will force-renew them.
This is helpful if you get an notification from 
let's encrypt that your should immediately renew your TLS certificate(s).

It will:

1) Query your Kubernetes cluster for all Certificate resources
2) Find all Secret resources managed by Certificate resources
3) Checks if the Secret resource contains a valid certificate and it contains the issuerName filter, if set.
4) Trigger cert-manager to renew any certificates that match the filter options.

## Getting started

First, clone and build a copy of the `k8s-letsencrypt-force-renew` tool from this GitHub repository.

First, perform a check of all the Certificates in your cluster and list them in the console:

```shell
./k8s-letsencrypt-force-renew 
```

Or you use the `issuerName` filter to only check for certificates that are issued by a specific issuer:

```shell
./k8s-letsencrypt-force-renew --issuerName letsencrypt-prod
```

You should see the tool check all resources in your cluster, and after a few seconds it should print something like:

```shell
...
2020/03/04 16:13:06 +++ Checking Secret resource for Certificate example/demo-prod
2020/03/04 16:13:13 Finished analyzing certificates, results:
2020/03/04 16:13:13   Skipped/unable to check: 0
2020/03/04 16:13:13   Affected certificates: 3
```

By default, the tool will NOT automatically trigger renewals, and will ONLY print out analysis information.

## Triggering a renewal

To actually trigger a renewal of these affected certificates, you must add the
`--renew` flag to your command invocation:

```shell
./k8s-letsencrypt-force-renew --issuerName letsencrypt-prod --renew
```

A number of warnings will be printed, giving you the opportunity to cancel in
case you have accidentally invoked the command incorrectly.

The tool will now go through and manually trigger a renewal for each affected
Certificate resource.

It does this by changing the `cert-manager.io/issuer-name` annotation on the
Secret resource for each certificate, causing cert-manager to re-request a
new certificate.

## Pre-requisites

This tool only works with **cert-manager v0.11 onwards**, as it depends on the
v1alpha2 API. If you are running an older version of cert-manager, please
upgrade by following the [upgrade guide](https://cert-manager.io/docs/installation/upgrading/).

Your Kubernetes user account will need the following permissions:

* Certificate resources (`cert-manager.io/v1alpha2`): LIST
* CertificateRequest resources (`cert-manager.io/v1alpha2`): LIST, DELETE
* Secret resources (`core/v1`): LIST, UPDATE

# Credits

This tool is inspired by the [letsencrypt-caa-bug-checker](https://github.com/jetstack/letsencrypt-caa-bug-checker). We use the same logic to check for CAA records and trigger cert-manager to renew certificates.
So thank you for the great work by Jetstack.