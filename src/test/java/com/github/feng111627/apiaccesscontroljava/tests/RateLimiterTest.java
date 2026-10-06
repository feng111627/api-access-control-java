package com.github.feng111627.apiaccesscontroljava.tests;

import com.github.feng111627.apiaccesscontroljava.ratelimit.RateLimitResult;
import com.github.feng111627.apiaccesscontroljava.ratelimit.RateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 覆盖限额：突发容量、限流拒绝与重试提示、并发不超发不漏计、调用方间隔离。
 */
class RateLimiterTest {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterTest.class);

    private RateLimiter rateLimiter;

    @BeforeEach
    void setUp(TestInfo info) {
        log.info("=== 用例开始: {} ===", info.getDisplayName());
        rateLimiter = new RateLimiter();
    }

    @Test
    @DisplayName("限额: 突发容量内全部放行, 超出即拒绝")
    void burstCapacityThenReject() {
        for (int i = 0; i < 10; i++) {
            assertTrue(rateLimiter.tryAcquire("c1", 5, 10).allowed(), "第 " + (i + 1) + " 个请求应放行");
        }
        RateLimitResult denied = rateLimiter.tryAcquire("c1", 5, 10);
        assertFalse(denied.allowed(), "超出突发容量应拒绝");
        log.info("10 个突发放行后第 11 个被拒, retryAfter={}s", denied.retryAfterSeconds());
    }

    @Test
    @DisplayName("限额: 拒绝时给出正的重试等待秒数")
    void rejectedCarriesRetryAfter() {
        for (int i = 0; i < 10; i++) {
            rateLimiter.tryAcquire("c1", 5, 10);
        }
        RateLimitResult denied = rateLimiter.tryAcquire("c1", 5, 10);
        assertFalse(denied.allowed());
        assertTrue(denied.retryAfterSeconds() >= 1, "重试提示至少 1 秒");
        log.info("被限流请求带可重试提示: retryAfter={}s", denied.retryAfterSeconds());
    }

    @Test
    @DisplayName("限额: 按速率补充后可再次放行")
    void refillAllowsAgain() throws InterruptedException {
        for (int i = 0; i < 5; i++) {
            rateLimiter.tryAcquire("c1", 20, 5); // 每秒补 20 个
        }
        assertFalse(rateLimiter.tryAcquire("c1", 20, 5).allowed());
        Thread.sleep(120); // 应补充约 2.4 个
        assertTrue(rateLimiter.tryAcquire("c1", 20, 5).allowed(), "补充后应放行");
        log.info("令牌按速率补充, 校验通过");
    }

    @Test
    @DisplayName("限额: 不同调用方互不影响")
    void callersAreIsolated() {
        for (int i = 0; i < 10; i++) {
            rateLimiter.tryAcquire("c1", 5, 10);
        }
        assertFalse(rateLimiter.tryAcquire("c1", 5, 10).allowed());
        assertTrue(rateLimiter.tryAcquire("c2", 5, 10).allowed(), "c2 应有独立额度");
        log.info("调用方间限额隔离, 校验通过");
    }

    @Test
    @DisplayName("并发: 200 线程突发抢 50 容量, 放行数精确等于 50(不超发不漏计)")
    void concurrentBurstNoOvershootNoUndercount() throws InterruptedException {
        int capacity = 50;
        int threads = 200;
        ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger denied = new AtomicInteger();
        List<Runnable> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> {
                ready.countDown();
                try {
                    go.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                if (rateLimiter.tryAcquire("hot-caller", 1, capacity).allowed()) {
                    allowed.incrementAndGet();
                } else {
                    denied.incrementAndGet();
                }
            });
        }
        tasks.forEach(pool::submit);
        assertTrue(ready.await(10, TimeUnit.SECONDS));
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        log.info("并发结果: allowed={}, denied={}, 总容量={}", allowed.get(), denied.get(), capacity);
        assertEquals(capacity, allowed.get(), "放行数必须精确等于桶容量, 不允许超发");
        assertEquals(threads - capacity, denied.get(), "其余请求必须全部被拒, 不允许漏计");
    }
}
