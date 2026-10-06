package com.github.feng111627.apiaccesscontroljava.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.apiaccesscontroljava.domain.AccessDecision;
import com.github.feng111627.apiaccesscontroljava.domain.AccessDecisionCode;
import com.github.feng111627.apiaccesscontroljava.security.AccessControlService;
import com.github.feng111627.apiaccesscontroljava.security.QuotaService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 访问控制过滤器：对受保护接口执行判定，并把结果映射为可区分的 HTTP 响应。
 * <ul>
 *   <li>ALLOW             → 放行</li>
 *   <li>MISSING_CREDENTIAL→ 401 + WWW-Authenticate（没带凭证）</li>
 *   <li>INVALID_CREDENTIAL→ 401（凭证无效/吊销/过期，文案不区分）</li>
 *   <li>FORBIDDEN         → 403（认证通过但无权限）</li>
 *   <li>RATE_LIMITED      → 429 + Retry-After（被限流，明确可重试）</li>
 * </ul>
 * 响应体与日志均不包含密钥原文；日志只记录 keyId（非敏感标识）与调用方自身 id。
 */
@Component
public class AccessControlFilter extends OncePerRequestFilter {

    /** 放行后在请求上暴露调用方 id 的属性名，业务接口可读取且无需再接触凭证。 */
    public static final String CALLER_ATTRIBUTE = "api.callerId";

    private static final Logger log = LoggerFactory.getLogger(AccessControlFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final AccessControlService accessControlService;
    private final QuotaService quotaService;
    private final ObjectMapper objectMapper;

    public AccessControlFilter(AccessControlService accessControlService,
                               QuotaService quotaService, ObjectMapper objectMapper) {
        this.accessControlService = accessControlService;
        this.quotaService = quotaService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String method = request.getMethod();
        String path = request.getRequestURI();
        String credentialHint = extractBearer(request);

        AccessDecision decision = accessControlService.decide(method, path, credentialHint);

        switch (decision.code()) {
            case ALLOW -> {
                log.info("access allowed method={} path={} caller={} keyId={}",
                        method, path, decision.callerId(), decision.keyId());
                if (decision.callerId() != null) {
                    request.setAttribute(CALLER_ATTRIBUTE, decision.callerId());
                }
                filterChain.doFilter(request, response);
            }
            case MISSING_CREDENTIAL -> reject(request, response, decision, HttpStatus.UNAUTHORIZED,
                    new ApiError("missing_credential",
                            "Authentication is required. Provide an Authorization: Bearer <credential> header.",
                            false), true, null);
            case INVALID_CREDENTIAL -> reject(request, response, decision, HttpStatus.UNAUTHORIZED,
                    new ApiError("invalid_credential",
                            "The provided credential is invalid, revoked or expired.",
                            false), true, null);
            case FORBIDDEN -> reject(request, response, decision, HttpStatus.FORBIDDEN,
                    new ApiError("forbidden",
                            "The caller is not permitted to access this endpoint.",
                            false), false, null);
            case RATE_LIMITED -> {
                long retryAfter = Math.max(1L, quotaService.retryAfterMillis(decision.callerId()));
                reject(request, response, decision, HttpStatus.TOO_MANY_REQUESTS,
                        new ApiError("rate_limited",
                                "Rate limit exceeded. Retry after the suggested delay.",
                                true), false, retryAfter);
            }
        }
    }

    private void reject(HttpServletRequest request, HttpServletResponse response,
                        AccessDecision decision, HttpStatus status, ApiError body,
                        boolean challenge, Long retryAfterMillis) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        if (challenge) {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        }
        if (retryAfterMillis != null) {
            // Retry-After 以秒为单位，向上取整至少 1 秒
            long retryAfterSeconds = Math.max(1L, (retryAfterMillis + 999L) / 1000L);
            response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(retryAfterSeconds));
        }
        // 日志只记录调用方自身标识与 keyId，不记录凭证原文，也不提及任何其他调用方
        log.warn("access denied method={} path={} code={} caller={} keyId={} retryAfterMs={}",
                request.getMethod(), request.getRequestURI(), decision.code(),
                decision.callerId(), decision.keyId(), retryAfterMillis);
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }

    private String extractBearer(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return null;
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }
}
