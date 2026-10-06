package com.github.feng111627.apiaccesscontroljava.tests;

import com.github.feng111627.apiaccesscontroljava.auth.Authenticator;
import com.github.feng111627.apiaccesscontroljava.auth.AuthorizationService;
import com.github.feng111627.apiaccesscontroljava.auth.CallerRegistry;
import com.github.feng111627.apiaccesscontroljava.auth.CredentialService;
import com.github.feng111627.apiaccesscontroljava.auth.RoutePermissions;
import com.github.feng111627.apiaccesscontroljava.model.Caller;
import com.github.feng111627.apiaccesscontroljava.ratelimit.RateLimiter;
import com.github.feng111627.apiaccesscontroljava.web.AccessControlFilter;
import com.github.feng111627.apiaccesscontroljava.web.DemoController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Duration;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * 覆盖过滤器端到端行为：公开接口、401 分级、403 无权限、429 限流带重试提示、
 * 响应不泄露凭证明文、吊销立即生效、轮换重叠窗口。
 */
class AccessControlFilterTest {

    private static final Logger log = LoggerFactory.getLogger(AccessControlFilterTest.class);

    private CredentialService credentialService;
    private MockMvc mvc;

    private String reportKey;
    private String adminKey;

    @BeforeEach
    void setUp(TestInfo info) {
        log.info("=== 用例开始: {} ===", info.getDisplayName());
        credentialService = new CredentialService();
        CallerRegistry callerRegistry = new CallerRegistry();
        callerRegistry.register(new Caller("caller-report", Set.of("reports:read"), 3, 3));
        callerRegistry.register(new Caller("caller-admin", Set.of("reports:read", "admin:config"), 100, 100));
        Authenticator authenticator = new Authenticator(credentialService, callerRegistry);
        AccessControlFilter filter = new AccessControlFilter(
                authenticator, new AuthorizationService(), new RoutePermissions(), new RateLimiter());
        mvc = MockMvcBuilders.standaloneSetup(new DemoController()).addFilter(filter, "/api/*").build();

        reportKey = credentialService.issue("caller-report", Duration.ofHours(1)).presented();
        adminKey = credentialService.issue("caller-admin", Duration.ofHours(1)).presented();
    }

    @Test
    @DisplayName("过滤器: 公开接口无需凭证")
    void publicEndpointNeedsNoCredential() throws Exception {
        mvc.perform(get("/api/public/hello")).andExpect(status().isOk());
        log.info("公开接口匿名访问 200");
    }

    @Test
    @DisplayName("过滤器: 未携带凭证 -> 401 CREDENTIAL_MISSING")
    void missingCredentialIs401() throws Exception {
        mvc.perform(get("/api/reports/summary"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("CREDENTIAL_MISSING"));
        log.info("未携带凭证 -> 401 CREDENTIAL_MISSING");
    }

    @Test
    @DisplayName("过滤器: 无效凭证 -> 401 CREDENTIAL_INVALID, 响应不含凭证原文")
    void invalidCredentialIs401AndDoesNotLeak() throws Exception {
        String fake = "key_deadbeef.wrongsecret";
        MvcResult result = mvc.perform(get("/api/reports/summary").header("X-Api-Key", fake))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("CREDENTIAL_INVALID"))
                .andReturn();
        String body = result.getResponse().getContentAsString();
        assertFalse(body.contains("wrongsecret"), "响应不得包含凭证原文");
        assertFalse(body.contains("caller-report"), "响应不得泄露其他调用方信息");
        log.info("无效凭证 -> 401, 响应体={}", body);
    }

    @Test
    @DisplayName("过滤器: 有权限 -> 200; 无权限 -> 403 PERMISSION_DENIED(与401区分)")
    void permissionDeniedIs403DistinctFrom401() throws Exception {
        mvc.perform(get("/api/reports/summary").header("X-Api-Key", reportKey))
                .andExpect(status().isOk());
        mvc.perform(get("/api/admin/config").header("X-Api-Key", reportKey))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PERMISSION_DENIED"));
        mvc.perform(get("/api/admin/config").header("X-Api-Key", adminKey))
                .andExpect(status().isOk());
        log.info("有权限 200 / 无权限 403, 与 401 明确区分");
    }

    @Test
    @DisplayName("过滤器: 超限 -> 429 RATE_LIMITED 且带 Retry-After 头")
    void rateLimitedIs429WithRetryAfter() throws Exception {
        for (int i = 0; i < 3; i++) {
            mvc.perform(get("/api/reports/summary").header("X-Api-Key", reportKey))
                    .andExpect(status().isOk());
        }
        mvc.perform(get("/api/reports/summary").header("X-Api-Key", reportKey))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("RATE_LIMITED"))
                .andExpect(header().exists("Retry-After"));
        log.info("第 4 个请求被限流 -> 429 + Retry-After, 与 403 无权限明确区分");
    }

    @Test
    @DisplayName("过滤器: 吊销后立即 401 CREDENTIAL_REVOKED")
    void revokedKeyFailsImmediately() throws Exception {
        var issued = credentialService.issue("caller-report", Duration.ofHours(1));
        mvc.perform(get("/api/reports/summary").header("X-Api-Key", issued.presented()))
                .andExpect(status().isOk());
        credentialService.revoke(issued.key().keyId());
        mvc.perform(get("/api/reports/summary").header("X-Api-Key", issued.presented()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("CREDENTIAL_REVOKED"));
        log.info("吊销后下一请求立即 401 CREDENTIAL_REVOKED");
    }

    @Test
    @DisplayName("过滤器: 轮换重叠窗口内新旧凭证都可用")
    void rotatedKeysBothWorkDuringOverlap() throws Exception {
        var newKey = credentialService.rotate("caller-admin", Duration.ofHours(1), Duration.ofMinutes(10));
        mvc.perform(get("/api/admin/config").header("X-Api-Key", adminKey))
                .andExpect(status().isOk());
        mvc.perform(get("/api/admin/config").header("X-Api-Key", newKey.presented()))
                .andExpect(status().isOk());
        log.info("重叠窗口内新旧凭证均 200");
    }
}
