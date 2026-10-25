package dev.authsync.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Serves the API at {@code <prefix>/api/...} as well as {@code /api/...}. Firebase Hosting forwards
 * same-origin requests such as {@code https://kalin.ga/lockstep/api/v1/bootstrap} to Cloud Run with the
 * path unchanged, so this maps them back to {@code /api/v1/bootstrap}. Requests that arrived this way are
 * marked, so the session cookie gets the browser-side path and the cookie name Firebase forwards.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class PublicPathPrefixFilter extends OncePerRequestFilter {
    /** Request attribute holding the public prefix (e.g. "/lockstep") when the request used it. */
    public static final String PREFIX_ATTRIBUTE = PublicPathPrefixFilter.class.getName() + ".prefix";
    private final String prefix;

    public PublicPathPrefixFilter(AuthSyncProperties properties) {
        this.prefix = normalize(properties.publicPathPrefix());
    }

    static String normalize(String value) {
        if (value == null || value.isBlank()) return "";
        String trimmed = value.trim();
        if (!trimmed.startsWith("/")) trimmed = "/" + trimmed;
        while (trimmed.endsWith("/")) trimmed = trimmed.substring(0, trimmed.length() - 1);
        return trimmed;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return prefix.isEmpty() || !request.getRequestURI().startsWith(prefix + "/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String uri = request.getRequestURI().substring(prefix.length());
        request.setAttribute(PREFIX_ATTRIBUTE, prefix);
        chain.doFilter(new HttpServletRequestWrapper(request) {
            @Override public String getRequestURI() { return uri; }
            @Override public String getServletPath() { return uri; }
            @Override public String getPathInfo() { return null; }
            @Override public StringBuffer getRequestURL() {
                StringBuffer url = new StringBuffer(super.getRequestURL());
                int start = url.indexOf(prefix + "/api/");
                if (start >= 0) url.delete(start, start + prefix.length());
                return url;
            }
        }, response);
    }
}
