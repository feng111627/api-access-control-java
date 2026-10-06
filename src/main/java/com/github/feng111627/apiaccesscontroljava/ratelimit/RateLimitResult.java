package com.github.feng111627.apiaccesscontroljava.ratelimit;

/**
 * 限额判定结果：是否放行，以及拒绝时的重试等待秒数。
 */
public record RateLimitResult(boolean allowed, long retryAfterSeconds) {

    public static RateLimitResult allow() {
        return new RateLimitResult(true, 0);
    }

    public static RateLimitResult deny(long retryAfterSeconds) {
        return new RateLimitResult(false, retryAfterSeconds);
    }
}
