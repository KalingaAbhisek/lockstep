package dev.authsync.config;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.cors.DefaultCorsProcessor;
import static org.assertj.core.api.Assertions.assertThat;
class CorsResponseHeadersTest {
 @Test void browserCanReadRetryAfterOnRateLimitResponse() throws Exception {
  var request=new MockHttpServletRequest("GET","/api/v1/entries");
  request.addHeader("Origin","https://web.example");
  var source=new SecurityConfig().corsConfigurationSource(new AuthSyncProperties("web","extension","https://web.example"));
  var response=new MockHttpServletResponse();response.setStatus(429);response.setHeader("Retry-After","60");
  assertThat(new DefaultCorsProcessor().processRequest(source.getCorsConfiguration(request),request,response)).isTrue();
  assertThat(response.getHeader("Access-Control-Expose-Headers")).contains("Retry-After");
  assertThat(response.getHeader("Retry-After")).isEqualTo("60");
 }
}
