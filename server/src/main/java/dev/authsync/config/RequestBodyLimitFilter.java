package dev.authsync.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Rejects oversized API request bodies with 413. Ordinary requests may send up to 1 MiB. A recovery-key
 * rotation re-uploads every account at once, so it may send up to 6 MiB (1,000 accounts at the largest
 * sizes the API accepts per account take about 4.5 MiB).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class RequestBodyLimitFilter extends OncePerRequestFilter {
    static final long MAX_BODY_BYTES = 1024 * 1024;
    static final long MAX_ROTATION_BODY_BYTES = 6L * 1024 * 1024;
    static final String ROTATION_PATH = "/api/v1/vault/rotate";

    /** Thrown while reading a body without a declared length once it passes the limit. */
    public static class BodyTooLargeException extends IOException {
        public BodyTooLargeException() { super("Request body is too large"); }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    static long limitFor(HttpServletRequest request) {
        return ROTATION_PATH.equals(request.getRequestURI()) ? MAX_ROTATION_BODY_BYTES : MAX_BODY_BYTES;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long limit = limitFor(request);
        if (request.getContentLengthLong() > limit) {
            tooLarge(response);
            return;
        }
        try {
            // Bodies without a declared length (chunked) are counted while they are read.
            chain.doFilter(new HttpServletRequestWrapper(request) {
                @Override
                public ServletInputStream getInputStream() throws IOException {
                    ServletInputStream delegate = super.getInputStream();
                    return new ServletInputStream() {
                        private long read;
                        @Override public int read() throws IOException {
                            int value = delegate.read();
                            if (value >= 0 && ++read > limit) throw new BodyTooLargeException();
                            return value;
                        }
                        @Override public int read(byte[] buffer, int offset, int length) throws IOException {
                            int count = delegate.read(buffer, offset, length);
                            if (count > 0 && (read += count) > limit) throw new BodyTooLargeException();
                            return count;
                        }
                        @Override public boolean isFinished() { return delegate.isFinished(); }
                        @Override public boolean isReady() { return delegate.isReady(); }
                        @Override public void setReadListener(ReadListener listener) { delegate.setReadListener(listener); }
                    };
                }
            }, response);
        } catch (BodyTooLargeException exception) {
            if (!response.isCommitted()) { response.reset(); tooLarge(response); }
        } catch (ServletException exception) {
            if (causedByTooLarge(exception) && !response.isCommitted()) { response.reset(); tooLarge(response); return; }
            throw exception;
        }
    }

    /** True when the exception (or one of its causes) is a body-size overflow. */
    public static boolean causedByTooLarge(Throwable exception) {
        for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
            if (cause instanceof BodyTooLargeException) return true;
            if (cause.getCause() == cause) break;
        }
        return false;
    }

    static void tooLarge(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"code\":\"REQUEST_TOO_LARGE\",\"error\":\"The request is too large.\"}");
    }
}
