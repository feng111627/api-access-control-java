package com.github.feng111627.apiaccesscontroljava.web;

import com.github.feng111627.apiaccesscontroljava.auth.AuthResult;
import com.github.feng111627.apiaccesscontroljava.auth.Authenticator;
import com.github.feng111627.apiaccesscontroljava.auth.AuthorizationService;
import com.github.feng111627.apiaccesscontroljava.auth.RoutePermissions;
import com.github.feng111627.apiaccesscontroljava.model.Caller;
import com.github.feng111627.apiaccesscontroljava.ratelimit.RateLimitResult;
import com.github.feng111627.apiaccesscontroljava.ratelimit.RateLimiter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * 访问控制过滤器：认证 -> 授权 -> 限额。
 *
 * 响应分级（彼此可明确区分）：
 * - 401 未携带/无效/已吊销/已过期凭证（code 细分，但不含凭证原文）
 * - 403 凭证有效但无权限
 * - 429 触发限额，带 Retry-After 头提示可重试
 *
 * 日志与响应只出现 keyId / callerId，绝不出现凭证明文；
 * 对无效凭证的响应不透露该 keyId 是否存在。
 */
public class AccessControlFilter extends OncePerRequestFilter {

    public static final String API_KEY_HEADER = "X-Api-Key";

    private static final Logger log = LoggerFactory.getLogger(AccessControlFilter.class);

    private final Authenticator authenticator;
    private final AuthorizationService authorizationService;
    private final RoutePermissions routePermissions;
    private final RateLimiter rateLimiter;

    public AccessControlFilter(Authenticator authenticator,
                               AuthorizationService authorizationService,
                               RoutePermissions routePermissions,
                               RateLimiter rateLimiter) {
        this.authenticator = authenticator;
        this.authorizationService = authorizationService;
        this.routePermissions = routePermissions;
        this.rateLimiter = rateLimiter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        Optional<String> required = routePermissions.requiredPermission(path);
        if (required.isEmpty()) {
            filterChain.doFilter(request, response); // 公开接口
            return;
        }

        AuthResult auth = authenticator.authenticate(request.getHeader(API_KEY_HEADER));
        if (auth.status() != AuthResult.Status.OK) {
            switch (auth.status()) {
                case MISSING -> reject(response, HttpStatus.UNAUTHORIZED, "CREDENTIAL_MISSING",
                        "missing credential");
                case REVOKED -> reject(response, HttpStatus.UNAUTHORIZED, "CREDENTIAL_REVOKED",
                        "credential has been revoked");
                case EXPIRED -> reject(response, HttpStatus.UNAUTHORIZED, "CREDENTIAL_EXPIRED",
                        "credential has expired");
                default -> reject(response, HttpStatus.UNAUTHORIZED, "CREDENTIAL_INVALID",
                        "invalid credential");
            }
            return;
        }

        Caller caller = auth.caller();
        if (!authorizationService.isAllowed(caller, required.get())) {
            log.info("访问拒绝(无权限): callerId={}, path={}, 所需权限={}", caller.id(), path, required.get());
            reject(response, HttpStatus.FORBIDDEN, "PERMISSION_DENIED",
                    "caller is not allowed to access this resource");
            return;
        }

        RateLimitResult rate = rateLimiter.tryAcquire(caller.id(), caller.permitsPerSecond(), caller.burstCapacity());
        if (!rate.allowed()) {
            response.setHeader("Retry-After", String.valueOf(rate.retryAfterSeconds()));
            reject(response, HttpStatus.TOO_MANY_REQUESTS, "RATE_LIMITED",
                    "rate limit exceeded, retry after " + rate.retryAfterSeconds() + "s");
            return;
        }

        log.debug("访问放行: callerId={}, keyId={}, path={}", caller.id(), auth.keyId(), path);
        request.setAttribute("callerId", caller.id());
        filterChain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response, HttpStatus status, String code, String message)
            throws IOException {
        log.info("请求被拒: status={}, code={}", status.value(), code);
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"code\":\"" + code + "\",\"message\":\"" + message + "\"}");
    }
}
