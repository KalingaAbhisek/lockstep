package dev.authsync.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class CspReportControllerTest {
    private final CspReportController controller = new CspReportController();

    @Test
    void readsBothReportFormatsWithoutQueryStrings() {
        String legacy = "{\"csp-report\":{\"document-uri\":\"https://kalin.ga/lockstep/?token=secret\",\"violated-directive\":\"require-trusted-types-for\","
                + "\"effective-directive\":\"require-trusted-types-for\",\"blocked-uri\":\"trusted-types-sink\",\"source-file\":\"https://accounts.google.com/gsi/client?x=1\",\"line-number\":12}}";
        assertThat(CspReportController.field(legacy, "effective-directive", "effectiveDirective")).isEqualTo("require-trusted-types-for");
        assertThat(CspReportController.withoutQuery(CspReportController.field(legacy, "document-uri", "documentURL"))).isEqualTo("https://kalin.ga/lockstep/");
        assertThat(CspReportController.withoutQuery(CspReportController.field(legacy, "source-file"))).isEqualTo("https://accounts.google.com/gsi/client");
        assertThat(CspReportController.field(legacy, "line-number")).isEqualTo("12");

        String reportingApi = "[{\"type\":\"csp-violation\",\"body\":{\"documentURL\":\"https://kalin.ga/lockstep/#x\",\"effectiveDirective\":\"script-src-elem\",\"blockedURL\":\"https://evil.example/x.js\"}}]";
        assertThat(CspReportController.field(reportingApi, "effective-directive", "effectiveDirective")).isEqualTo("script-src-elem");
        assertThat(CspReportController.withoutQuery(CspReportController.field(reportingApi, "documentURL"))).isEqualTo("https://kalin.ga/lockstep/");
    }

    @Test
    void cannotForgeLogLinesOrFloodTheLog() {
        assertThat(CspReportController.clean("a\\nFAKE LOG LINE\u0007")).isEqualTo("a FAKE LOG LINE?");
        assertThat(CspReportController.clean("x".repeat(500))).hasSize(201);
        int accepted = 0;
        for (int i = 0; i < 50; i++) if (controller.tryAcquire("203.0.113.9")) accepted++;
        assertThat(accepted).isEqualTo(CspReportController.MAX_REPORTS_PER_MINUTE);
        assertThat(controller.tryAcquire("198.51.100.1")).isTrue();
    }

    @Test
    void answersWithoutContentEvenForGarbage() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", CspReportController.PATH);
        request.setContent("not json at all".getBytes());
        assertThat(controller.report(request).getStatusCode().value()).isEqualTo(204);
    }
}
