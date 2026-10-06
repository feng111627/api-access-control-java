package com.github.feng111627.apiaccesscontroljava.domain;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

/**
 * 令牌桶：CAS 无锁实现，保证突发并发下不超发、不漏计。
 * <p>
 * 桶状态（当前令牌数、上次填充时间戳）作为一个不可变整体被替换：
 * 每次 {@link #tryAcquire()} 都基于同一个快照完成"补充令牌 + 扣减 + 提交"，
 * 提交通过 CAS 保证只有一个线程成功，竞争者带着最新快照重试，
 * 因此并发请求要么完整消耗一个令牌，要么不消耗，不会出现撕裂判定。
 */
public class TokenBucket {

    /** 桶内不可变快照状态。 */
    public record State(double tokens, long lastRefillNanos) {
    }

    private static final long NANOS_PER_SECOND = 1_000_000_000L;

    private final double capacity;
    private final double refillTokensPerSecond;
    private final AtomicReference<State> state;
    private final LongSupplier nanoTime;

    public TokenBucket(double capacity, double refillTokensPerSecond, long nowNanos, LongSupplier nanoTime) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        if (refillTokensPerSecond < 0) {
            throw new IllegalArgumentException("refillTokensPerSecond must not be negative");
        }
        this.capacity = capacity;
        this.refillTokensPerSecond = refillTokensPerSecond;
        this.nanoTime = nanoTime;
        // 新桶默认是满的：允许一次性打满 capacity 的突发
        this.state = new AtomicReference<>(new State(capacity, nowNanos));
    }

    /**
     * 尝试获取一个令牌。
     *
     * @return true 放行；false 已被限流（本次不扣减任何令牌）
     */
    public boolean tryAcquire() {
        while (true) {
            State snapshot = state.get();
            long now = nanoTime.getAsLong();
            State refilled = refill(snapshot, now);
            if (refilled.tokens() < 1.0d) {
                // 令牌不足：若期间状态已被其他线程推进，则继续重试读取，否则判定限流
                if (state.compareAndSet(snapshot, refilled)) {
                    return false;
                }
                continue;
            }
            // refill 仅基于 snapshot 推导、尚未提交；直接以 snapshot 为期望值一次性提交
            State next = new State(refilled.tokens() - 1.0d, refilled.lastRefillNanos());
            if (state.compareAndSet(snapshot, next)) {
                return true;
            }
            // CAS 失败说明有并发请求先行，拿最新状态重试，绝不重复扣减
        }
    }

    private State refill(State snapshot, long nowNanos) {
        long elapsed = nowNanos - snapshot.lastRefillNanos();
        if (elapsed <= 0) {
            return snapshot;
        }
        double added = (elapsed * refillTokensPerSecond) / NANOS_PER_SECOND;
        if (added <= 0.0d) {
            // 时间推进了但不够补一个最小令牌单位，只更新时间戳
            return new State(snapshot.tokens(), nowNanos);
        }
        double tokens = Math.min(capacity, snapshot.tokens() + added);
        return new State(tokens, nowNanos);
    }

    /**
     * 距离可获得下一个令牌还需等待的毫秒数（用于 Retry-After），最小 1ms。
     * 调用方应在 tryAcquire 返回 false 后读取，仅作建议值。
     */
    public long retryAfterMillis() {
        State snapshot = state.get();
        double missing = 1.0d - snapshot.tokens();
        if (missing <= 0.0d) {
            return 0L;
        }
        if (refillTokensPerSecond <= 0.0d) {
            // 不补充令牌的桶，给一个较大的保守值
            return 3600_000L;
        }
        double waitSeconds = missing / refillTokensPerSecond;
        long waitMillis = (long) Math.ceil(waitSeconds * 1000.0d);
        return Math.max(1L, waitMillis);
    }

    public double currentTokens() {
        return state.get().tokens();
    }

    public double capacity() {
        return capacity;
    }
}
