package dev.authsync.account;

import com.google.cloud.firestore.Firestore;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.ExecutionException;

@RestController
@RequestMapping("/api/v1/account")
public class AccountController {
    private final Firestore firestore;

    public AccountController(Firestore firestore) {
        this.firestore = firestore;
    }

    @GetMapping
    AccountStatus status(@AuthenticationPrincipal Jwt jwt) {
        try {
            boolean exists = firestore.collection("users").document(jwt.getSubject()).get().get().exists();
            return new AccountStatus(exists);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Account lookup was interrupted", exception);
        } catch (ExecutionException exception) {
            throw new IllegalStateException("Account lookup failed", exception.getCause());
        }
    }

    public record AccountStatus(boolean exists) {}
}
