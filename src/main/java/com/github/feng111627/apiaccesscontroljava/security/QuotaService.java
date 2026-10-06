package com.github.feng111627.apiaccesscontroljava.security;

import com.github.feng111627.apiaccesscontroljava.domain.TokenBucket;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * 按调用方维度的配额服务（令牌桶）。
 * <p>
 * 每个调用方拥有独立的 {@link TokenBucket}；桶内"补充 + 扣减"是单次 CAS 原子操作，
 * 因此突发并发下每个被放行的请求都恰好消耗一个令牌，绝不超发；
 * 被限流的请求不消耗令牌，不漏计后续配额。
 */
@Component
public class QuotaService {

    /** 默认桶容量（突发上限）。 */
    public static final double DEFAULT_CAPACITY = 10.0d;
    /** 默认每秒补充令牌数（持续速率）。 */
    public static final double DEFAULT_REFILL_PER_SECOND = 1.0d;

    private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();
    private final Clock clock;
    private final LongSupplier nanoTime;

    @Autowired
    public QuotaService(Clock clock) {
        this(clock, System::nanoTime);
    }

    /** 测试用构造：可注入可控纳秒时钟。 */
    QuotaService(Clock clock, LongSupplier nanoTime) {
        this.clock = clock;
        this.nanoTime = nanoTime;
    }

    /**
     * 配置（或重置）调用方配额。会以一个满桶替换旧桶，通常用于初始化或管理面调额。
     */
    public void configure(String callerId, double capacity, double refillPerSecond) {
        if (callerId == null) {
            throw new IllegalArgumentException("callerId must not be null");
        }
        buckets.put(callerId, newBucket(capacity, refillPerSecond));
    }

    /**
     * 尝试消耗一个令牌。
     *
     * @return 消耗成功返回 true；配额耗尽返回 false
     */
    public boolean tryAcquire(String callerId) {
        return buckets.computeIfAbsent(callerId,
                id -> newBucket(DEFAULT_CAPACITY, DEFAULT_REFILL_PER_SECOND)).tryAcquire();
    }

    /** 建议的重试等待毫秒数（用于 Retry-After 响应头）。 */
    public long retryAfterMillis(String callerId) {
        TokenBucket bucket = buckets.get(callerId);
        return bucket == null ? 1000L : bucket.retryAfterMillis();
    }

    /** 测试/管理用途：重置某调用方桶为默认满桶；不存在则无效。 */
    public void reset(String callerId) {
        buckets.computeIfPresent(callerId,
                (id, old) -> newBucket(old.capacity(), DEFAULT_REFILL_PER_SECOND));
    }

    private TokenBucket newBucket(double capacity, double refillPerSecond) {
        return new TokenBucket(capacity, refillPerSecond, nanoTime.getAsLong(), nanoTime);
    }
}
