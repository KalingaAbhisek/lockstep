package dev.authsync.vault;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.List;
import static org.assertj.core.api.Assertions.*;
class ResetEnumerationTest {
 @Test void stalledEnumerationTimesOut() {
  long deadline=System.nanoTime()+Duration.ofMillis(50).toNanos();
  assertThatThrownBy(()->VaultResetService.enumerate(()->{Thread.sleep(10000);return List.of("late");},100,deadline))
   .isInstanceOf(dev.authsync.config.FirestoreCalls.DatabaseUnavailableException.class);
 }
 @Test void enumerationIsBoundedAndExpiredWorkIsRejected() {
  assertThat(VaultResetService.enumerate(()->List.of(1,2,3),2,System.nanoTime()+Duration.ofSeconds(1).toNanos())).containsExactly(1,2);
  assertThatThrownBy(()->VaultResetService.enumerate(()->{throw new AssertionError("must not start");},1,System.nanoTime()-1))
   .isInstanceOf(dev.authsync.config.FirestoreCalls.DatabaseUnavailableException.class);
 }
}
