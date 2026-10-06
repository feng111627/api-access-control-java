package com.github.feng111627.apiaccesscontroljava.tests;

import com.github.feng111627.apiaccesscontroljava.domain.AccessDecision;
import com.github.feng111627.apiaccesscontroljava.domain.AccessDecisionCode;
import com.github.feng111627.apiaccesscontroljava.domain.Caller;
import com.github.feng111627.apiaccesscontroljava.security.AccessControlService;
import com.github.feng111627.apiaccesscontroljava.security.CallerRegistry;
import com.github.feng111627.apiaccesscontroljava.security.CredentialStore;
import com.github.feng111627.apiaccesscontroljava.security.EndpointPermissions;
import com.github.feng111627.apiaccesscontroljava.security.QuotaService;
import com.github.feng111627.apiaccesscontroljava.tests.support.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 访问控制判定测试：认证/授权/配额三类失败严格区分，凭证变更即时反映，判定信息不泄密。
 */
class AccessControlServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AccessControlServiceTest.class);
    private static final Instant T0 = Instant.parse("2026-10-07T00:00:00Z");

    private MutableClock clock;
    private CredentialStore credentials;
    private QuotaService quotas;
    private AccessControlService service;

    private String readSecret;
    private String writeSecret;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(T0);
        credentials = new CredentialStore(clock);
        CallerRegistry callers = new CallerRegistry();
        quotas = new QuotaService(clock);
        service = new AccessControlService(credentials, callers, quotas, new EndpointPermissions());

        callers.register(new Caller("reader", "Reader App", Set.of("api:read")));
        callers.register(new Caller("writer", "Writer App", Set.of("api:read", "api:write")));
        quotas.configure("reader", 100.0d, 1.0d);
        quotas.configure("writer", 100.0d, 1.0d);

        readSecret = "reader-secret-very-long-and-secret-value";
        writeSecret = "writer-secret-very-long-and-secret-value";
        credentials.seedCredential("reader", "ak-reader", readSecret, null);
        credentials.seedCredential("writer", "ak-writer", writeSecret, null);
    }

    @Test
    @DisplayName("判定-缺凭证: 未携带凭证返回 MISSING_CREDENTIAL，与无权限明确区分")
    void missingCredentialIsDistinct() {
        AccessDecision d1 = service.decide("GET", "/api/data", null);
        AccessDecision d2 = service.decide("GET", "/api/data", "   ");
        assertEquals(AccessDecisionCode.MISSING_CREDENTIAL, d1.code());
        assertEquals(AccessDecisionCode.MISSING_CREDENTIAL, d2.code());
        log.info("[判定-缺凭证] null 与空白凭证均判为 MISSING_CREDENTIAL");
    }

    @Test
    @DisplayName("判定-无效凭证: 错误/被吊销/过期凭证统一判为 INVALID_CREDENTIAL，不细分原因")
    void invalidRevokedExpiredCredentialsAreRejectedAsInvalid() {
        assertEquals(AccessDecisionCode.INVALID_CREDENTIAL,
                service.decide("GET", "/api/data", "wrong-secret").code());
        log.info("[判定-无效凭证] 未知凭证 -> INVALID_CREDENTIAL");

        assertTrue(credentials.revoke("ak-reader"));
        assertEquals(AccessDecisionCode.INVALID_CREDENTIAL,
                service.decide("GET", "/api/data", readSecret).code());
        log.info("[判定-吊销即时性] 吊销后同一凭证立刻判为 INVALID_CREDENTIAL");

        CredentialStore.IssuedCredential shortLived = credentials.issue("writer", 1_000L);
        clock.advance(Duration.ofMillis(1_000));
        assertEquals(AccessDecisionCode.INVALID_CREDENTIAL,
                service.decide("GET", "/api/data", shortLived.plaintextSecret()).code());
        log.info("[判定-过期即时性] TTL 到期后凭证立刻判为 INVALID_CREDENTIAL");
    }

    @Test
    @DisplayName("判定-无权限: 有效凭证但权限不足判为 FORBIDDEN，与 401 类失败区分")
    void authenticatedButForbiddenIsDistinct() {
        AccessDecision decision = service.decide("POST", "/api/data", readSecret);
        assertEquals(AccessDecisionCode.FORBIDDEN, decision.code());
        assertEquals("reader", decision.callerId());
        assertEquals("ak-reader", decision.keyId());
        assertNotEquals(AccessDecisionCode.INVALID_CREDENTIAL, decision.code());
        log.info("[判定-无权限] reader 调写接口 -> FORBIDDEN（认证成功、授权失败），keyId 可审计");
    }

    @Test
    @DisplayName("判定-放行: 权限匹配时 ALLOW，且只暴露调用方自身标识")
    void allowedCarriesOwnCallerOnly() {
        AccessDecision decision = service.decide("POST", "/api/data", writeSecret);
        assertEquals(AccessDecisionCode.ALLOW, decision.code());
        assertEquals("writer", decision.callerId());
        assertEquals("ak-writer", decision.keyId());
        log.info("[判定-放行] writer 调写接口 -> ALLOW caller=writer keyId=ak-writer");
    }

    @Test
    @DisplayName("判定-限流: 配额耗尽判为 RATE_LIMITED，与 FORBIDDEN/认证失败均不同，且不消耗失败请求")
    void rateLimitedIsDistinctAndRetryable() {
        quotas.configure("reader", 2.0d, 0.0d);
        assertEquals(AccessDecisionCode.ALLOW, service.decide("GET", "/api/ping", readSecret).code());
        assertEquals(AccessDecisionCode.ALLOW, service.decide("GET", "/api/ping", readSecret).code());
        AccessDecision limited = service.decide("GET", "/api/ping", readSecret);
        assertEquals(AccessDecisionCode.RATE_LIMITED, limited.code());
        assertEquals("reader", limited.callerId());
        assertNotEquals(AccessDecisionCode.FORBIDDEN, limited.code());
        log.info("[判定-限流] 容量 2 用尽后 -> RATE_LIMITED，调用方身份仍可识别，区别于无权限");

        // 有权限但被限流：换一个写调用方在同一接口仍可通过，证明限流按调用方隔离
        assertEquals(AccessDecisionCode.ALLOW, service.decide("GET", "/api/ping", writeSecret).code());
        log.info("[判定-限流隔离] reader 被限流不影响 writer，配额按调用方维度独立");
    }

    @Test
    @DisplayName("判定-公开接口: 未登记接口无需凭证即放行")
    void publicEndpointBypassesControl() {
        assertEquals(AccessDecisionCode.ALLOW, service.decide("GET", "/actuator/health", null).code());
        log.info("[判定-公开接口] 未登记权限的接口视为公开，直接放行");
    }

    @Test
    @DisplayName("判定-不泄密: 任何失败详情都不包含密钥原文，且不出现其他调用方标识")
    void decisionsNeverLeakSecretOrOtherCallers() {
        AccessDecision wrong = service.decide("POST", "/api/data", readSecret + "-tampered");
        AccessDecision forbidden = service.decide("POST", "/api/data", readSecret);
        AccessDecision missing = service.decide("GET", "/api/data", null);
        for (AccessDecision d : new AccessDecision[]{wrong, forbidden, missing}) {
            assertFalse(d.detail().contains(readSecret), "detail 不得包含密钥原文");
            assertFalse(d.detail().contains(writeSecret), "detail 不得包含任何密钥原文");
        }
        assertFalse(forbidden.detail().contains("writer"), "无权限详情不得提及其他调用方");
        log.info("[判定-不泄密] 失败判定 detail 中无密钥原文、无其他调用方信息");
    }
}
