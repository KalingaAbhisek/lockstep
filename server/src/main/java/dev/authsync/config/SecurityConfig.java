package dev.authsync.config;

import dev.authsync.session.ClientSessionValidationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class SecurityConfig {
    private static final java.util.Set<String> GOOGLE_ISSUERS = java.util.Set.of("https://accounts.google.com", "accounts.google.com");

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, ClientSessionValidationFilter clientSessionValidationFilter) throws Exception {
        return http
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
                .cors(Customizer.withDefaults())
                .headers(headers -> headers
                        .crossOriginOpenerPolicy(coop -> coop.policy(CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS))
                        .referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)))
                .authorizeHttpRequests(auth -> auth
                        .dispatcherTypeMatchers(jakarta.servlet.DispatcherType.ASYNC).permitAll()
                        .requestMatchers("/api/v1/config", "/actuator/health", "/error").permitAll()
                        // Browsers send security-policy reports without signing in (see CspReportController).
                        .requestMatchers(HttpMethod.POST, "/api/v1/csp-report").permitAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().permitAll())
                .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()))
                .addFilterAfter(clientSessionValidationFilter, BearerTokenAuthenticationFilter.class)
                .addFilterAfter(new RequestRateLimitFilter(), ClientSessionValidationFilter.class)
                .build();
    }

    @Bean
    NimbusJwtDecoder jwtDecoder(AuthSyncProperties properties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri("https://www.googleapis.com/oauth2/v3/certs").build();
        // Google ID tokens use either issuer spelling; accept both (plus the default expiry checks).
        OAuth2TokenValidator<Jwt> issuer = new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefault(),
                new JwtClaimValidator<Object>(JwtClaimNames.ISS,
                        value -> value != null && GOOGLE_ISSUERS.contains(value.toString())));
        OAuth2TokenValidator<Jwt> audience = new GoogleAudienceValidator(properties.googleClientIds());
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(issuer, audience));
        return decoder;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(AuthSyncProperties properties) {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(properties.allowedOriginList());
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Lockstep-Client", "X-Lockstep-Session", "X-Lockstep-Subject", "X-Lockstep-Session-Mode"));
        configuration.setExposedHeaders(List.of("Retry-After"));
        configuration.setAllowCredentials(false);
        // Browsers may remember a preflight answer for this long (Chrome caps it at two hours), so the web app
        // does not send an extra OPTIONS request before almost every API call.
        configuration.setMaxAge(7200L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Browsers send security-policy reports from whichever site the web app runs on (also with the
        // same-origin proxy, when that site may not be in ALLOWED_ORIGINS). They carry no credentials and
        // are rate-limited, so any origin may send them. Registered first: the first matching path wins.
        CorsConfiguration reports = new CorsConfiguration();
        reports.setAllowedOriginPatterns(List.of("*"));
        reports.setAllowedMethods(List.of("POST", "OPTIONS"));
        reports.setAllowedHeaders(List.of("Content-Type"));
        reports.setAllowCredentials(false);
        source.registerCorsConfiguration("/api/v1/csp-report", reports);
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }
}

