package com.example.containeranalysisfunction;

import com.google.api.gax.core.CredentialsProvider;
import com.google.cloud.devtools.containeranalysis.v1.ContainerAnalysisClient;
import com.google.cloud.devtools.containeranalysis.v1.ContainerAnalysisSettings;
import com.google.gson.Gson;
import io.grafeas.v1.GrafeasClient;
import io.grafeas.v1.NoteKind;
import io.grafeas.v1.Occurrence;
import io.grafeas.v1.Severity;
import io.grafeas.v1.VulnerabilityOccurrence;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.function.Consumer;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class ContainerAnalysisFunctionApplication {
  private static Logger logger =
      LoggerFactory.getLogger(ContainerAnalysisFunctionApplication.class);

  public static void main(String[] args) {
    SpringApplication.run(ContainerAnalysisFunctionApplication.class, args);
  }

  @Bean
  Gson gson() {
    return new Gson();
  }

  @Bean(destroyMethod = "shutdownNow")
  ContainerAnalysisClient containerAnalysisClient(CredentialsProvider credentialsProvider)
      throws IOException {
    return ContainerAnalysisClient.create(
        ContainerAnalysisSettings.newBuilder().setCredentialsProvider(credentialsProvider).build());
  }

  @Bean
  Consumer<PubSubMessage> occurrenceConsumer(Gson gson, ContainerAnalysisClient client) {
    return (in) -> {
      String json = new String(Base64.getDecoder().decode(in.getData()), StandardCharsets.UTF_8);
      OccurrenceNotification notification = gson.fromJson(json, OccurrenceNotification.class);

      try {
        GrafeasClient grafeasClient = client.getGrafeasClient();
        Occurrence occurrence = grafeasClient.getOccurrence(notification.getName());
        if (NoteKind.VULNERABILITY.equals(occurrence.getKind())) {
          VulnerabilityOccurrence vulnerability = occurrence.getVulnerability();
          if (vulnerability.getSeverity().getNumber() >= Severity.HIGH_VALUE) {
            logger.warn(
                String.format(
                    "Image: %s, CVE: %s, Severity: %s",
                    occurrence.getResourceUri(),
                    vulnerability.getShortDescription(),
                    vulnerability.getSeverity()));
          }
        }
      } catch (IOException e) {
        logger.error("error getting grafeas client", e);
      }
    };
  }
}

@Data
class PubSubMessage {
  private String data;
  private Map<String, String> attributes;
  private String messageId;
  private String publishTime;
}

@Data
class OccurrenceNotification {
  private String name;
  private String kind;
  private String notificationTime;
}
