package dev.authsync.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.NoCredentials;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.FirestoreOptions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

@Configuration
public class FirebaseConfig {
    @Bean(destroyMethod = "close")
    Firestore firestore(AuthSyncProperties properties) {
        if (isClassCacheTrainingRun()) return trainingFirestore(properties);
        String credentialsPath = properties.firebaseCredentialsPath();
        if (credentialsPath == null || credentialsPath.isBlank()) {
            return firestore(properties, applicationDefaultCredentials());
        }
        Path path = Path.of(credentialsPath).toAbsolutePath().normalize();
        try (InputStream input = Files.newInputStream(path)) {
            return firestore(properties, GoogleCredentials.fromStream(input));
        } catch (IOException exception) {
            throw new IllegalStateException("Unable to read Firebase credentials from " + path, exception);
        }
    }

    private static Firestore firestore(AuthSyncProperties properties, GoogleCredentials credentials) {
        FirestoreOptions.Builder options = FirestoreOptions.newBuilder().setCredentials(credentials);
        if (properties.firebaseProjectId() != null && !properties.firebaseProjectId().isBlank()) {
            options.setProjectId(properties.firebaseProjectId());
        }
        return options.build().getService();
    }

    /**
     * The Docker build starts the application once with -Dspring.context.exit=onRefresh to record a
     * class-data-sharing archive (faster startup). That run has no credentials and must not touch the
     * network, so it gets a client that is never used: the JVM exits as soon as the context is ready.
     */
    private static boolean isClassCacheTrainingRun() {
        return "onRefresh".equals(System.getProperty("spring.context.exit"));
    }

    private static Firestore trainingFirestore(AuthSyncProperties properties) {
        String projectId = properties.firebaseProjectId();
        return FirestoreOptions.newBuilder()
                .setCredentials(NoCredentials.getInstance())
                .setProjectId(projectId == null || projectId.isBlank() ? "lockstep-class-cache-training" : projectId)
                .build().getService();
    }

    private static GoogleCredentials applicationDefaultCredentials() {
        try {
            return GoogleCredentials.getApplicationDefault();
        } catch (IOException exception) {
            throw new IllegalStateException(
                    "Firebase credentials are unavailable. Set GOOGLE_APPLICATION_CREDENTIALS or configure Application Default Credentials.",
                    exception);
        }
    }
}
