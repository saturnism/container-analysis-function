This is an example Google Cloud Function that can listen to Pub/Sub events from
[Container Analysis](https://cloud.google.com/container-registry/docs/container-analysis)'
[Vulnerability Scanning](https://cloud.google.com/container-registry/docs/vulnerability-scanning) feature,
and create an log entry so that you can use Log-based Metrics to create a Cloud Ops Alert, and
send a notification when new container image vulnerability is detected.

To use this:
1. [Enable Container Analysis API](https://cloud.google.com/container-registry/docs/enabling-disabling-container-analysis)
1. Deploy this function
1. Create Log-based metrics and extract labels from `Image`, `CVE`, and `Severity`.

Once the metric is configured, you can then graph and/or setup alerts based on the count of
entries group by the image name, and let Cloud Ops send the alerts.

Enable Container Analysis:
```
gcloud services enable containeranalysis.googleapis.com
```

Build and Deploy this function:
```
./mvnw package

gcloud functions deploy occurrences-consumer \                                                             ↵ INT
--entry-point org.springframework.cloud.function.adapter.gcp.GcfJarLauncher \
--runtime java11 \
--trigger-topic container-analysis-occurrences-v1 \
--source target/deploy \
--memory 512MB
```

Deploy the Log-based Metrics configuration:
```
gcloud beta logging metrics create container-vulnerability --config-from-file=cloudops/container-analysis-metrics.yaml
```

Deploy the Alert Policy configuration:
```
gcloud alpha monitoring policies create --policy-from-file=cloudops/vulnerability-policy.yaml
```

This configuration doesn't configure any notification channels. To get notified via e-mail, or Slack
see [Manging notification channels documentation](https://cloud.google.com/monitoring/support/notification-options)


## Development
Run Locally:
```
./mvnw function:run
```

Build:
```
./mvnw clean package
```

