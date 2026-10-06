package com.github.feng111627.apiaccesscontroljava.tests;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.feng111627.apiaccesscontroljava.security.QuotaService;

import java.time.Clock;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 配额服务测试：按调用方隔离、默认桶、并发不超发。
 */
class QuotaServiceTest {

    private static final Logger log = LoggerFactory.getLogger(QuotaServiceTest.class);

    @Test
    @DisplayName("配额服务: 桶按调用方隔离，一方耗尽不影响另一方；未配置调用方使用默认桶")
    void bucketsAreIsolatedPerCaller() {
        QuotaService service = new QuotaService(Clock.systemUTC());
        service.configure("a", 2.0d, 0.0d);

        assertTrue(service.tryAcquire("a"));
        assertTrue(service.tryAcquire("a"));
        assertFalse(service.tryAcquire("a"), "a 的桶应耗尽");
        assertTrue(service.tryAcquire("b"), "b 拥有独立桶，不受 a 影响");
        assertTrue(service.tryAcquire("newcomer"), "未配置调用方使用默认容量桶");
        log.info("[配额隔离] a 耗尽后 b 与新调用方仍可请求，桶严格按调用方隔离");
    }

    @Test
    @DisplayName("配额服务-并发: 多个调用方高并发请求时，每个调用方都不超过自身容量")
    void concurrentRequestsNeverOversellAcrossCallers() throws InterruptedException {
        QuotaService service = new QuotaService(Clock.systemUTC());
        service.configure("a", 10.0d, 0.0d);
        service.configure("b", 5.0d, 0.0d);

        int threadsPerCaller = 100;
        ExecutorService pool = Executors.newFixedThreadPool(32);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threadsPerCaller * 2);
        AtomicInteger allowedA = new AtomicInteger();
        AtomicInteger allowedB = new AtomicInteger();

        for (int i = 0; i < threadsPerCaller; i++) {
            pool.submit(() -> runOne(start, done, service, "a", allowedA));
            pool.submit(() -> runOne(start, done, service, "b", allowedB));
        }
        start.countDown();
        assertTrue(done.await(15, TimeUnit.SECONDS));
        pool.shutdown();

        assertEquals(10, allowedA.get(), "调用方 a 不能超发");
        assertEquals(5, allowedB.get(), "调用方 b 不能超发");
        log.info("[配额服务-并发] 每调用方 100 线程竞争：a 放行 {}（容量10），b 放行 {}（容量5），均无超发",
                allowedA.get(), allowedB.get());
    }

    private static void runOne(CountDownLatch start, CountDownLatch done,
                               QuotaService service, String caller, AtomicInteger counter) {
        try {
            start.await();
            if (service.tryAcquire(caller)) {
                counter.incrementAndGet();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            done.countDown();
        }
    }
}
