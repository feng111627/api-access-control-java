package com.github.feng111627.apiaccesscontroljava.ratelimit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

/**
 * 按调用方限额的令牌桶限流器。
 *
 * 并发正确性：每个调用方一个桶，取令牌在桶对象上 synchronized，
 * "补充-判断-扣减"是同一个临界区，突发高并发下不会超发也不会漏计。
 * 被限流时返回 retryAfterSeconds：按当前速率攒够一个令牌所需的秒数（向上取整，至少 1 秒）。
 */
@Component
public class RateLimiter {

    private static final Logger log = LoggerFactory.getLogger(RateLimiter.class);

    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimitResult tryAcquire(String callerId, int permitsPerSecond, int burstCapacity) {
        Bucket bucket = buckets.computeIfAbsent(callerId, id -> new Bucket());
        boolean allowed = bucket.tryAcquire(permitsPerSecond, burstCapacity);
        if (allowed) {
            return RateLimitResult.allow();
        }
        long wait = bucket.secondsUntilNextPermit(permitsPerSecond, burstCapacity);
        log.info("限流拒绝: callerId={}, retryAfterSeconds={}", callerId, wait);
        return RateLimitResult.deny(wait);
    }

    /** 仅供测试/运维观察当前桶内令牌数。 */
    public double availablePermits(String callerId, int permitsPerSecond, int burstCapacity) {
        Bucket bucket = buckets.get(callerId);
        if (bucket == null) {
            return burstCapacity;
        }
        synchronized (bucket) {
            bucket.refill(permitsPerSecond, burstCapacity);
            return bucket.tokens;
        }
    }

    private static final class Bucket {
        private double tokens = -1; // -1 表示尚未初始化
        private long lastRefillNanos;

        synchronized boolean tryAcquire(int permitsPerSecond, int burstCapacity) {
            refill(permitsPerSecond, burstCapacity);
            if (tokens >= 1.0) {
                tokens -= 1.0;
                return true;
            }
            return false;
        }

        synchronized long secondsUntilNextPermit(int permitsPerSecond, int burstCapacity) {
            refill(permitsPerSecond, burstCapacity);
            if (tokens >= 1.0) {
                return 0;
            }
            double deficit = 1.0 - tokens;
            return Math.max(1, (long) Math.ceil(deficit / permitsPerSecond));
        }

        private void refill(int permitsPerSecond, int burstCapacity) {
            long now = System.nanoTime();
            if (tokens < 0) { // 首次使用：桶是满的
                tokens = burstCapacity;
                lastRefillNanos = now;
                return;
            }
            double elapsedSeconds = (now - lastRefillNanos) / 1_000_000_000.0;
            tokens = Math.min(burstCapacity, tokens + elapsedSeconds * permitsPerSecond);
            lastRefillNanos = now;
        }
    }
}
