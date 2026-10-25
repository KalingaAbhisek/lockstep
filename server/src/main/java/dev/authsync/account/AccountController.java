package dev.authsync.account;

import com.google.cloud.firestore.Firestore;
import dev.authsync.lock.FirestoreLockSettingsRepository;
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
        // A reset vault leaves only bookkeeping fields behind; that is not an existing account.
        boolean exists = FirestoreLockSettingsRepository.accountExists(dev.authsync.config.FirestoreCalls.await(
                firestore.collection("users").document(jwt.getSubject()).get(), "Account lookup"));
        return new AccountStatus(exists);
    }

    public record AccountStatus(boolean exists) {}
}
