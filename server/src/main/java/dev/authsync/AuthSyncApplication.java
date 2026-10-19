package dev.authsync;

import dev.authsync.config.DotEnvLoader;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class AuthSyncApplication {
    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(AuthSyncApplication.class);
        application.setDefaultProperties(DotEnvLoader.load());
        application.run(args);
    }
}

