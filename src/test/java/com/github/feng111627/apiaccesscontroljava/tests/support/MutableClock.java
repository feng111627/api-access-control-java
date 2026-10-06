package com.github.feng111627.apiaccesscontroljava.tests.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * 测试用可控时钟：可显式前进时间，用于验证凭证过期与轮换重叠窗口。
 */
public class MutableClock extends Clock {

    private Instant instant;
    private final ZoneId zone;

    public MutableClock(Instant initial) {
        this(initial, ZoneOffset.UTC);
    }

    public MutableClock(Instant initial, ZoneId zone) {
        this.instant = initial;
        this.zone = zone;
    }

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return new MutableClock(instant, zone);
    }

    @Override
    public Instant instant() {
        return instant;
    }

    @Override
    public long millis() {
        return instant.toEpochMilli();
    }

    public void advance(Duration duration) {
        this.instant = instant.plus(duration);
    }

    public void setInstant(Instant instant) {
        this.instant = instant;
    }
}
