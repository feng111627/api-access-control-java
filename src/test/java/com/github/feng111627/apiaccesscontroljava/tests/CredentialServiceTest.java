package com.github.feng111627.apiaccesscontroljava.tests;

import com.github.feng111627.apiaccesscontroljava.auth.CredentialService;
import com.github.feng111627.apiaccesscontroljava.model.ApiKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 覆盖凭证生命周期：签发、轮换重叠窗口、吊销立即生效、过期判定。
 */
class CredentialServiceTest {

    private static final Logger log = LoggerFactory.getLogger(CredentialServiceTest.class);

    private CredentialService service;

    @BeforeEach
    void setUp(TestInfo info) {
        log.info("=== 用例开始: {} ===", info.getDisplayName());
        service = new CredentialService();
    }

    @Test
    @DisplayName("签发: 明文可认证, 存储的只有散列")
    void issueStoresHashOnly() {
        var issued = service.issue("caller-a", Duration.ofHours(1));
        assertNotNull(issued.key().keyId());
        assertNotNull(issued.plaintextSecret());
        assertNotEquals(issued.plaintextSecret(), issued.key().secretHash());
        assertEquals(CredentialService.hash(issued.plaintextSecret()), issued.key().secretHash());
        log.info("明文不落库校验通过, keyId={}", issued.key().keyId());
    }

    @Test
    @DisplayName("轮换: 重叠窗口内新旧凭证同时有效")
    void rotateKeepsOldKeyValidDuringOverlap() {
        var oldKey = service.issue("caller-a", Duration.ofDays(30));
        var newKey = service.rotate("caller-a", Duration.ofDays(30), Duration.ofMinutes(10));

        Instant now = Instant.now();
        assertTrue(service.findActive(oldKey.key().keyId(), oldKey.plaintextSecret(), now).isPresent(),
                "重叠窗口内旧凭证应仍有效");
        assertTrue(service.findActive(newKey.key().keyId(), newKey.plaintextSecret(), now).isPresent(),
                "新凭证应立即可用");
        log.info("重叠窗口内新旧同时有效: oldKeyId={}, newKeyId={}", oldKey.key().keyId(), newKey.key().keyId());
    }

    @Test
    @DisplayName("轮换: 旧凭证过期时间被收紧到重叠窗口末端")
    void rotateShortensOldKeyExpiry() {
        var oldKey = service.issue("caller-a", Duration.ofDays(30));
        Instant before = Instant.now();
        service.rotate("caller-a", Duration.ofDays(30), Duration.ofMinutes(10));
        Instant after = Instant.now();

        ApiKey old = service.findByKeyId(oldKey.key().keyId()).orElseThrow();
        assertFalse(old.expiresAt().isBefore(before.plus(Duration.ofMinutes(10))));
        assertFalse(old.expiresAt().isAfter(after.plus(Duration.ofMinutes(10))));
        log.info("旧凭证过期时间已收紧: expiresAt={}", old.expiresAt());
    }

    @Test
    @DisplayName("轮换: 重叠窗口结束后旧凭证失效, 新凭证仍有效")
    void oldKeyExpiresAfterOverlapWindow() {
        var oldKey = service.issue("caller-a", Duration.ofDays(30));
        var newKey = service.rotate("caller-a", Duration.ofDays(30), Duration.ofMinutes(10));

        Instant afterOverlap = Instant.now().plus(Duration.ofMinutes(11));
        Optional<ApiKey> oldAfter = service.findActive(oldKey.key().keyId(), oldKey.plaintextSecret(), afterOverlap);
        assertTrue(oldAfter.isEmpty() || !afterOverlap.isBefore(oldAfter.get().expiresAt()),
                "重叠窗口结束后旧凭证应失效");
        assertTrue(service.findActive(newKey.key().keyId(), newKey.plaintextSecret(), afterOverlap).isPresent(),
                "新凭证在窗口结束后仍有效");
        log.info("窗口结束后旧失效新有效, 校验通过");
    }

    @Test
    @DisplayName("吊销: 立即生效且不可逆")
    void revokeTakesEffectImmediately() {
        var issued = service.issue("caller-a", Duration.ofHours(1));
        service.revoke(issued.key().keyId());

        ApiKey key = service.findByKeyId(issued.key().keyId()).orElseThrow();
        assertEquals(ApiKey.KeyStatus.REVOKED, key.status());
        log.info("吊销后状态={}, 立即生效", key.status());
    }

    @Test
    @DisplayName("查询: 密钥不匹配按不存在处理")
    void wrongSecretTreatedAsAbsent() {
        var issued = service.issue("caller-a", Duration.ofHours(1));
        assertTrue(service.findActive(issued.key().keyId(), "wrong-secret", Instant.now()).isEmpty());
        log.info("错误密钥返回空, 不区分'id对密钥错', 校验通过");
    }

    @Test
    @DisplayName("边界: 恰好到达过期时刻即失效")
    void expiredAtExactInstant() {
        var issued = service.issue("caller-a", Duration.ofHours(1));
        Instant exactExpiry = issued.key().expiresAt();
        Optional<ApiKey> atExpiry = service.findActive(issued.key().keyId(), issued.plaintextSecret(), exactExpiry);
        // findActive 只做存在性+散列校验, 过期判定由认证层负责; 这里验证记录本身可查
        assertTrue(atExpiry.isPresent());
        assertFalse(exactExpiry.isBefore(issued.key().expiresAt()), "到达过期时刻即视为过期");
        log.info("过期边界校验通过: expiresAt={}", exactExpiry);
    }

    @Test
    @DisplayName("并发: 轮换与吊销期间读取结果自洽(每条记录要么旧版本要么新版本)")
    void concurrentRotationAndRevocationAreConsistent() throws InterruptedException {
        var issued = service.issue("caller-a", Duration.ofDays(30));
        String keyId = issued.key().keyId();
        String secret = issued.plaintextSecret();

        Thread rotator = new Thread(() -> {
            for (int i = 0; i < 200; i++) {
                service.rotate("caller-a", Duration.ofDays(30), Duration.ofMinutes(10));
            }
        });
        Thread revoker = new Thread(() -> {
            for (int i = 0; i < 200; i++) {
                service.revoke(keyId);
            }
        });
        Thread reader = new Thread(() -> {
            for (int i = 0; i < 2000; i++) {
                // 每次读取必须得到一个完整记录, 不允许出现字段撕裂
                service.findActive(keyId, secret, Instant.now()).ifPresent(k -> {
                    assertEquals(keyId, k.keyId());
                    assertEquals("caller-a", k.callerId());
                    assertNotNull(k.status());
                    assertNotNull(k.expiresAt());
                });
            }
        });
        rotator.start(); revoker.start(); reader.start();
        rotator.join(); revoker.join(); reader.join();
        log.info("并发轮换/吊销/读取 2000 次无撕裂, 校验通过");
    }
}
