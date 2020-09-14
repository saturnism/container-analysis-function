## Introduction 
This is an example Google Cloud Function that can listen to Pub/Sub events from
[Container Analysis](https://cloud.google.com/container-registry/docs/container-analysis)'
[Vulnerability Scanning](https://cloud.google.com/container-registry/docs/vulnerability-scanning) feature,
and create an log entry so that you can use Log-based Metrics to create a Cloud Ops Alert, and
send a notification when new container image vulnerability is detected.

In general, this is how it works:
1. [Enable Container Analysis API](https://cloud.google.com/container-registry/docs/enabling-disabling-container-analysis)
1. This will also automatically create Pub/Sub topics to publish scanning results
1. [Occurrences](https://cloud.google.com/container-registry/docs/metadata-storage#occurrence) (vulnerabilities on an image) is published to the `container-analysis-occurrences-v1` topic
1. Deploy a Function that analyzes the notification, and print the result to log
1. Create a Log-based metrics, and extract the `Image` name, `CVE`, and `Severity`
1. Create an alert policy on this metrics, and count the vulnerabilities grouped by the image name
1. FInally, you can configure a [notification channel](https://cloud.google.com/monitoring/support/notification-options) to get notified

## Detailed Steps
Enable Container Analysis:
```
gcloud services enable containeranalysis.googleapis.com
```

Build and Deploy this function:
```
./mvnw package

gcloud functions deploy occurrences-consumer \
  --entry-point org.springframework.cloud.function.adapter.gcp.GcfJarLauncher \
  --runtime java11 \
  --trigger-topic container-analysis-occurrences-v1 \
  --source target/deploy \
  --memory 512MB
```

Deploy the Log-based Metrics configuration:
```
gcloud beta logging metrics create container-vulnerability \
  --config-from-file=cloudops/container-analysis-metrics.yaml
```

Deploy the Alert Policy configuration:
```
gcloud alpha monitoring policies create \
  --policy-from-file=cloudops/vulnerability-policy.yaml
```

This configuration doesn't configure any notification channels. To get notified via e-mail, or Slack
see [Manging notification channels documentation](https://cloud.google.com/monitoring/support/notification-options).

## Development
Run Locally:
```
./mvnw function:run
```

Build:
```
./mvnw clean package
```

