package com.github.feng111627.apiaccesscontroljava.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * 统一时钟 Bean，便于测试中替换为可控时钟（轮换重叠窗口、凭证过期等）。
 */
@Configuration
public class ClockConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
