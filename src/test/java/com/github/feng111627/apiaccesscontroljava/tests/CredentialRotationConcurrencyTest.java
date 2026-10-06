package com.github.feng111627.apiaccesscontroljava.tests;

import com.github.feng111627.apiaccesscontroljava.domain.CredentialStatus;
import com.github.feng111627.apiaccesscontroljava.security.CredentialStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 轮换/吊销与并发请求的自洽性测试。
 */
class CredentialRotationConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(CredentialRotationConcurrencyTest.class);

    @Test
    @DisplayName("凭证-轮换并发: 重叠窗口内对旧证的并发认证全部成功，不出现时好时坏")
    void concurrentAuthDuringOverlapIsStable() throws InterruptedException {
        CredentialStore store = new CredentialStore(Clock.systemUTC());
        CredentialStore.IssuedCredential old = store.issue("caller-a", null);

        int readers = 32;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(readers);
        ExecutorService pool = Executors.newFixedThreadPool(readers);
        AtomicInteger successes = new AtomicInteger();
        AtomicBoolean rotationDone = new AtomicBoolean();

        // 重叠窗口 30 秒，确保读线程全部运行在窗口内
        pool.submit(() -> {
            try {
                start.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            store.rotate("caller-a", null, 30_000L);
            rotationDone.set(true);
        });

        for (int i = 0; i < readers; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    // 等轮换发生后再密集认证旧证
                    while (!rotationDone.get()) {
                        Thread.onSpinWait();
                    }
                    if (store.findActiveBySecret(old.plaintextSecret()).isPresent()) {
                        successes.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(15, TimeUnit.SECONDS));
        pool.shutdown();

        assertEquals(readers, successes.get(),
                "重叠窗口内旧凭证的并发认证必须全部成功，不能因竞争出现间歇性失败");
        log.info("[凭证-轮换并发] 轮换后 {} 个并发请求用旧证认证，成功 {}（重叠窗口内判定完全自洽）",
                readers, successes.get());
    }

    @Test
    @DisplayName("凭证-吊销并发: 吊销发布后所有新认证立即失败，不存在吊销后仍成功的请求")
    void concurrentAuthSeesRevocationImmediately() throws InterruptedException {
        CredentialStore store = new CredentialStore(Clock.systemUTC());
        CredentialStore.IssuedCredential issued = store.issue("caller-b", null);

        // 先制造"吊销前可能成功、吊销后必须失败"的分界点：以 revoke 返回为界
        assertTrue(store.revoke(issued.keyId()));
        int attempts = 64;
        AtomicInteger postRevokeHits = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch done = new CountDownLatch(attempts);
        for (int i = 0; i < attempts; i++) {
            pool.submit(() -> {
                try {
                    if (store.findActiveBySecret(issued.plaintextSecret()).isPresent()) {
                        postRevokeHits.incrementAndGet();
                    }
                } finally {
                    done.countDown();
                }
            });
        }
        assertTrue(done.await(10, TimeUnit.SECONDS));
        pool.shutdown();

        assertEquals(0, postRevokeHits.get(), "吊销返回之后不允许任何请求再认证成功");
        assertEquals(CredentialStatus.REVOKED, store.findByKeyId(issued.keyId()).orElseThrow().status());
        assertFalse(store.findActiveBySecret(issued.plaintextSecret()).isPresent());
        log.info("[凭证-吊销并发] 吊销发布后 {} 个并发认证全部失败，吊销即时可见", attempts);
    }
}
