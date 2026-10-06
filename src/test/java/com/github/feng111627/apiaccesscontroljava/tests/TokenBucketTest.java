package com.github.feng111627.apiaccesscontroljava.tests;

import com.github.feng111627.apiaccesscontroljava.domain.TokenBucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 令牌桶配额测试：覆盖突发上限、匀速补充、零补充、并发不超发与不漏计。
 */
class TokenBucketTest {

    private static final Logger log = LoggerFactory.getLogger(TokenBucketTest.class);

    @Test
    @DisplayName("配额-突发: 容量为 N 时前 N 个请求放行，第 N+1 个被限流且不消耗令牌")
    void burstCapacityIsBoundedAndRejectionsDontConsume() {
        NanoClock clock = new NanoClock(0L);
        TokenBucket bucket = new TokenBucket(3.0d, 0.0d, 0L, clock::get);

        for (int i = 1; i <= 3; i++) {
            assertTrue(bucket.tryAcquire(), "第 " + i + " 个请求应在突发容量内放行");
        }
        log.info("[配额-突发] 容量 3 内 3 次请求全部放行");

        assertFalse(bucket.tryAcquire(), "第 4 个请求应被限流");
        assertFalse(bucket.tryAcquire(), "被限流的请求不应消耗令牌，继续限流");
        assertEquals(0.0d, bucket.currentTokens(), 1e-9, "限流后桶内令牌应为 0");
        log.info("[配额-突发] 超出容量的请求稳定返回限流，且未漏计/超发");
    }

    @Test
    @DisplayName("配额-补充: 按每秒速率匀速回填，且不超过容量上限")
    void tokensRefillAtConfiguredRate() {
        NanoClock clock = new NanoClock(0L);
        TokenBucket bucket = new TokenBucket(3.0d, 10.0d, 0L, clock::get);

        for (int i = 0; i < 3; i++) {
            assertTrue(bucket.tryAcquire());
        }
        assertFalse(bucket.tryAcquire());
        log.info("[配额-补充] 打满突发后清空令牌");

        clock.advance(200_000_000L); // 前进 0.2 秒 -> 补充 2 个令牌
        assertTrue(bucket.tryAcquire(), "0.2 秒后应有 2 个令牌（第 1 个）");
        assertTrue(bucket.tryAcquire(), "0.2 秒后应有 2 个令牌（第 2 个）");
        assertFalse(bucket.tryAcquire(), "第 3 个仍应限流");
        log.info("[配额-补充] 按 10/s 速率在 0.2s 后恰好补充 2 个令牌");

        clock.advance(10_000_000_000L); // 前进 10 秒，远超填满时间
        for (int i = 0; i < 3; i++) {
            assertTrue(bucket.tryAcquire(), "补充后的令牌数不应超过容量 3");
        }
        assertFalse(bucket.tryAcquire());
        log.info("[配额-补充] 长时间等待后回填被容量上限截断为 3");
    }

    @Test
    @DisplayName("配额-重试提示: 限流时给出正的等待毫秒数")
    void retryAfterIsPositiveWhenEmpty() {
        TokenBucket bucket = new TokenBucket(1.0d, 2.0d, 0L, () -> 0L);
        assertTrue(bucket.tryAcquire());
        long wait = bucket.retryAfterMillis();
        assertTrue(wait >= 400 && wait <= 600, "2/s 速率下等待应约 500ms，实际=" + wait);
        log.info("[配额-重试提示] 建议重试等待 {}ms", wait);
    }

    @Test
    @DisplayName("配额-并发: 100 线程同时抢 50 个令牌，放行数恰好为 50，无超发")
    void concurrentAcquisitionsNeverExceedCapacity() throws InterruptedException {
        int threads = 100;
        NanoClock clock = new NanoClock(0L);
        TokenBucket bucket = new TokenBucket(50.0d, 0.0d, 0L, clock::get);

        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger allowed = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    if (bucket.tryAcquire()) {
                        allowed.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        pool.shutdown();

        assertEquals(50, allowed.get(), "并发放行数必须恰好等于容量，不能超发");
        assertEquals(0.0d, bucket.currentTokens(), 1e-9, "剩余令牌应为 0，不能漏计");
        log.info("[配额-并发] {} 个线程竞争 50 令牌，实际放行 {}，无超发无漏计", threads, allowed.get());
    }

    /** 仅前进时间的最小纳秒时钟。 */
    private static final class NanoClock {
        private volatile long value;

        private NanoClock(long value) {
            this.value = value;
        }

        long get() {
            return value;
        }

        void advance(long delta) {
            this.value += delta;
        }
    }
}
