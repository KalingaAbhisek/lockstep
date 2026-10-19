package dev.authsync.vault;

import com.google.cloud.firestore.Firestore;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.ExecutionException;

@RestController
@RequestMapping("/api/v1/vault")
public class VaultController {
    private final Firestore firestore;

    public VaultController(Firestore firestore) {
        this.firestore = firestore;
    }

    @DeleteMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void reset(@AuthenticationPrincipal Jwt jwt) {
        try {
            firestore.recursiveDelete(firestore.collection("users").document(jwt.getSubject())).get();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Vault reset was interrupted", exception);
        } catch (ExecutionException exception) {
            throw new IllegalStateException("Vault reset failed", exception.getCause());
        }
    }
}
