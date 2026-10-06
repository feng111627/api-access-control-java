package com.github.feng111627.apiaccesscontroljava.tests;

import com.github.feng111627.apiaccesscontroljava.domain.Credential;
import com.github.feng111627.apiaccesscontroljava.domain.CredentialStatus;
import com.github.feng111627.apiaccesscontroljava.security.CredentialStore;
import com.github.feng111627.apiaccesscontroljava.tests.support.MutableClock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 凭证存储测试：覆盖签发查找、过期边界、吊销即时性、轮换重叠窗口与状态可解释性。
 */
class CredentialStoreTest {

    private static final Logger log = LoggerFactory.getLogger(CredentialStoreTest.class);
    private static final Instant T0 = Instant.parse("2026-10-07T00:00:00Z");

    private final MutableClock clock = new MutableClock(T0);
    private final CredentialStore store = new CredentialStore(clock);

    @Test
    @DisplayName("凭证-认证: 签发后可凭原文查到；错误/空原文一律查不到且不区分原因")
    void issueAndLookupOnlyWithExactSecret() {
        CredentialStore.IssuedCredential issued = store.issue("caller-a", null);
        log.info("[凭证-认证] 签发 keyId={}（密钥仅返回一次）", issued.keyId());

        Optional<Credential> hit = store.findActiveBySecret(issued.plaintextSecret());
        assertTrue(hit.isPresent());
        assertEquals("caller-a", hit.get().callerId());
        assertEquals(CredentialStatus.ACTIVE, hit.get().status());

        assertTrue(store.findActiveBySecret("not-the-secret").isEmpty());
        assertTrue(store.findActiveBySecret(" ").isEmpty());
        assertTrue(store.findActiveBySecret(null).isEmpty());
        log.info("[凭证-认证] 错误/空白凭证均返回空，错误原因不被区分");
    }

    @Test
    @DisplayName("凭证-过期: 到达 expiresAt 时刻立即失效并惰性标记为 EXPIRED（边界 now==expiresAt）")
    void credentialExpiresExactlyAtTtlBoundary() {
        CredentialStore.IssuedCredential issued = store.issue("caller-a", 1_000L);

        clock.advance(Duration.ofMillis(999));
        assertTrue(store.findActiveBySecret(issued.plaintextSecret()).isPresent(),
                "到期前 1ms 仍应有效");
        log.info("[凭证-过期] 到期前 999ms 仍有效");

        clock.advance(Duration.ofMillis(1));
        assertTrue(store.findActiveBySecret(issued.plaintextSecret()).isEmpty(),
                "now==expiresAt 时应立即失效");
        Credential snapshot = store.findByKeyId(issued.keyId()).orElseThrow();
        assertEquals(CredentialStatus.EXPIRED, snapshot.status(),
                "过期后快照状态应可解释为 EXPIRED");
        log.info("[凭证-过期] 到达到期时刻立即失效，状态={}，后续请求全部拒绝", snapshot.status());
    }

    @Test
    @DisplayName("凭证-吊销: 吊销立即生效且幂等，状态可解释为 REVOKED")
    void revokeIsImmediateAndIdempotent() {
        CredentialStore.IssuedCredential issued = store.issue("caller-a", null);

        assertTrue(store.revoke(issued.keyId()), "首次吊销返回 true");
        assertTrue(store.findActiveBySecret(issued.plaintextSecret()).isEmpty(),
                "吊销后必须立即不可用");
        assertFalse(store.revoke(issued.keyId()), "重复吊销返回 false（幂等）");
        assertFalse(store.revoke("ak-never-exists"), "吊销不存在的凭证返回 false");
        assertEquals(CredentialStatus.REVOKED, store.findByKeyId(issued.keyId()).orElseThrow().status());
        log.info("[凭证-吊销] keyId={} 吊销即时生效，重复/不存在吊销均幂等返回 false", issued.keyId());
    }

    @Test
    @DisplayName("凭证-轮换: 重叠窗口内新旧都有效；窗口结束旧证立即失效、新证继续有效")
    void rotationOverlapWindowThenOldExpires() {
        CredentialStore.IssuedCredential old = store.issue("caller-a", null);

        clock.advance(Duration.ofSeconds(10));
        CredentialStore.IssuedCredential fresh = store.rotate("caller-a", null, 5_000L);
        log.info("[凭证-轮换] t=10s 轮换：新证 {} 生效，旧证 {} 重叠窗口 5s",
                fresh.keyId(), old.keyId());

        for (int i = 0; i < 3; i++) {
            clock.advance(Duration.ofSeconds(1));
            assertTrue(store.findActiveBySecret(old.plaintextSecret()).isPresent(),
                    "窗口内旧证必须持续有效，不能时好时坏");
            assertTrue(store.findActiveBySecret(fresh.plaintextSecret()).isPresent(),
                    "窗口内新证必须持续有效");
        }
        log.info("[凭证-轮换] 重叠窗口 t=11~13s 内新旧凭证均 100% 有效，判定自洽");

        clock.advance(Duration.ofMillis(2_001)); // 到达 t=15.001s，超出 now(10s)+5s
        assertTrue(store.findActiveBySecret(old.plaintextSecret()).isEmpty(),
                "重叠窗口结束旧证必须立即失效");
        assertTrue(store.findActiveBySecret(fresh.plaintextSecret()).isPresent(),
                "窗口结束后新证继续有效");
        assertEquals(CredentialStatus.EXPIRED, store.findByKeyId(old.keyId()).orElseThrow().status());
        log.info("[凭证-轮换] 窗口结束旧证 EXPIRED，新证保持 ACTIVE");
    }

    @Test
    @DisplayName("凭证-轮换: 旧证自身 TTL 早于重叠窗口结束时，以更早时间为准")
    void rotationRespectsEarlierOriginalExpiry() {
        // t=0 签发，t=8s 到期
        CredentialStore.IssuedCredential old = store.issue("caller-a", 8_000L);
        clock.advance(Duration.ofSeconds(5));
        // t=5 轮换，重叠窗口 1 小时，但旧证 t=8 就到期
        CredentialStore.IssuedCredential fresh = store.rotate("caller-a", null, 3_600_000L);

        clock.advance(Duration.ofSeconds(4)); // t=9，旧证已过自身 TTL
        assertTrue(store.findActiveBySecret(old.plaintextSecret()).isEmpty());
        assertTrue(store.findActiveBySecret(fresh.plaintextSecret()).isPresent());
        log.info("[凭证-轮换-边界] 旧证 TTL(8s) 早于重叠窗口结束，按 TTL 失效");
    }

    @Test
    @DisplayName("凭证-轮换: 调用方无凭证时轮换抛出明确异常")
    void rotateWithoutCredentialFails() {
        assertThrows(IllegalStateException.class, () -> store.rotate("nobody", null, 1_000L));
        log.info("[凭证-轮换-边界] 无凭证调用方轮换被明确拒绝");
    }
}
