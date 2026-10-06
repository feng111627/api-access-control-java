package com.github.feng111627.apiaccesscontroljava.tests;

import com.github.feng111627.apiaccesscontroljava.auth.AuthResult;
import com.github.feng111627.apiaccesscontroljava.auth.Authenticator;
import com.github.feng111627.apiaccesscontroljava.auth.CallerRegistry;
import com.github.feng111627.apiaccesscontroljava.auth.CredentialService;
import com.github.feng111627.apiaccesscontroljava.model.Caller;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 覆盖认证判定：未携带 / 格式非法 / 无效 / 吊销 / 过期 / 成功，以及轮换重叠窗口。
 */
class AuthenticatorTest {

    private static final Logger log = LoggerFactory.getLogger(AuthenticatorTest.class);

    private CredentialService credentialService;
    private CallerRegistry callerRegistry;
    private Authenticator authenticator;

    @BeforeEach
    void setUp(TestInfo info) {
        log.info("=== 用例开始: {} ===", info.getDisplayName());
        credentialService = new CredentialService();
        callerRegistry = new CallerRegistry();
        authenticator = new Authenticator(credentialService, callerRegistry);
        callerRegistry.register(new Caller("caller-a", Set.of("reports:read"), 5, 10));
    }

    @Test
    @DisplayName("认证: 未携带凭证 -> MISSING")
    void missingCredential() {
        assertEquals(AuthResult.Status.MISSING, authenticator.authenticate(null).status());
        assertEquals(AuthResult.Status.MISSING, authenticator.authenticate("  ").status());
        log.info("未携带凭证判定为 MISSING, 与无权限区分");
    }

    @Test
    @DisplayName("认证: 格式非法 -> INVALID")
    void malformedCredential() {
        assertEquals(AuthResult.Status.INVALID, authenticator.authenticate("no-dot-here").status());
        assertEquals(AuthResult.Status.INVALID, authenticator.authenticate(".secret").status());
        assertEquals(AuthResult.Status.INVALID, authenticator.authenticate("keyid.").status());
        log.info("格式非法判定为 INVALID");
    }

    @Test
    @DisplayName("认证: 有效凭证 -> OK 且识别出调用方")
    void validCredential() {
        var issued = credentialService.issue("caller-a", Duration.ofHours(1));
        AuthResult result = authenticator.authenticate(issued.presented());
        assertEquals(AuthResult.Status.OK, result.status());
        assertEquals("caller-a", result.caller().id());
        log.info("有效凭证认证通过, callerId={}", result.caller().id());
    }

    @Test
    @DisplayName("认证: 密钥错误 -> INVALID(不区分id对错)")
    void wrongSecret() {
        var issued = credentialService.issue("caller-a", Duration.ofHours(1));
        AuthResult result = authenticator.authenticate(issued.key().keyId() + ".wrongsecret");
        assertEquals(AuthResult.Status.INVALID, result.status());
        log.info("密钥错误判定为 INVALID");
    }

    @Test
    @DisplayName("认证: 已吊销 -> REVOKED, 与无效/过期区分")
    void revokedCredential() {
        var issued = credentialService.issue("caller-a", Duration.ofHours(1));
        credentialService.revoke(issued.key().keyId());
        AuthResult result = authenticator.authenticate(issued.presented());
        assertEquals(AuthResult.Status.REVOKED, result.status());
        log.info("吊销凭证判定为 REVOKED");
    }

    @Test
    @DisplayName("认证: 已过期 -> EXPIRED")
    void expiredCredential() throws InterruptedException {
        var issued = credentialService.issue("caller-a", Duration.ofMillis(50));
        Thread.sleep(80);
        AuthResult result = authenticator.authenticate(issued.presented());
        assertEquals(AuthResult.Status.EXPIRED, result.status());
        log.info("过期凭证判定为 EXPIRED");
    }

    @Test
    @DisplayName("认证: 吊销优先于过期(显式动作优先)")
    void revokedTakesPrecedenceOverExpired() throws InterruptedException {
        var issued = credentialService.issue("caller-a", Duration.ofMillis(50));
        credentialService.revoke(issued.key().keyId());
        Thread.sleep(80);
        assertEquals(AuthResult.Status.REVOKED, authenticator.authenticate(issued.presented()).status());
        log.info("既吊销又过期时判定为 REVOKED");
    }

    @Test
    @DisplayName("认证: 轮换重叠窗口内新旧凭证都判定 OK")
    void bothKeysValidDuringRotationOverlap() {
        var oldKey = credentialService.issue("caller-a", Duration.ofDays(1));
        var newKey = credentialService.rotate("caller-a", Duration.ofDays(1), Duration.ofMinutes(10));
        assertEquals(AuthResult.Status.OK, authenticator.authenticate(oldKey.presented()).status());
        assertEquals(AuthResult.Status.OK, authenticator.authenticate(newKey.presented()).status());
        log.info("重叠窗口内新旧凭证均 OK");
    }

    @Test
    @DisplayName("认证: 凭证指向未知调用方 -> INVALID(不泄露内部状态)")
    void unknownCaller() {
        var issued = credentialService.issue("ghost-caller", Duration.ofHours(1));
        assertEquals(AuthResult.Status.INVALID, authenticator.authenticate(issued.presented()).status());
        log.info("未知调用方判定为 INVALID");
    }
}
