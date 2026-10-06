package com.github.feng111627.apiaccesscontroljava.config;

import com.github.feng111627.apiaccesscontroljava.auth.Authenticator;
import com.github.feng111627.apiaccesscontroljava.auth.AuthorizationService;
import com.github.feng111627.apiaccesscontroljava.auth.CallerRegistry;
import com.github.feng111627.apiaccesscontroljava.auth.CredentialService;
import com.github.feng111627.apiaccesscontroljava.auth.RoutePermissions;
import com.github.feng111627.apiaccesscontroljava.model.Caller;
import com.github.feng111627.apiaccesscontroljava.ratelimit.RateLimiter;
import com.github.feng111627.apiaccesscontroljava.web.AccessControlFilter;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.Set;

/**
 * 访问控制装配：注册过滤器、内置演示调用方。
 */
@Configuration
public class AccessControlConfig {

    private static final Logger log = LoggerFactory.getLogger(AccessControlConfig.class);

    private final CallerRegistry callerRegistry;
    private final CredentialService credentialService;

    public AccessControlConfig(CallerRegistry callerRegistry, CredentialService credentialService) {
        this.callerRegistry = callerRegistry;
        this.credentialService = credentialService;
    }

    @Bean
    public FilterRegistrationBean<AccessControlFilter> accessControlFilter(
            Authenticator authenticator,
            AuthorizationService authorizationService,
            RoutePermissions routePermissions,
            RateLimiter rateLimiter) {
        FilterRegistrationBean<AccessControlFilter> bean = new FilterRegistrationBean<>(
                new AccessControlFilter(authenticator, authorizationService, routePermissions, rateLimiter));
        bean.addUrlPatterns("/api/*");
        bean.setOrder(1);
        return bean;
    }

    /** 演示数据：两个调用方，权限与限额不同。明文密钥只在此打印一次。 */
    @PostConstruct
    void seedDemoCallers() {
        callerRegistry.register(new Caller("caller-report", Set.of("reports:read"), 5, 10));
        callerRegistry.register(new Caller("caller-admin", Set.of("reports:read", "admin:config"), 5, 10));
        var reportKey = credentialService.issue("caller-report", Duration.ofDays(30));
        var adminKey = credentialService.issue("caller-admin", Duration.ofDays(30));
        log.info("演示凭证(仅启动时显示一次): caller-report -> {}", reportKey.presented());
        log.info("演示凭证(仅启动时显示一次): caller-admin  -> {}", adminKey.presented());
    }
}
