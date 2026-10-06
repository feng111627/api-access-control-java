package com.github.feng111627.apiaccesscontroljava.model;

import java.util.Set;

/**
 * 调用方身份：权限集合与限额配置。
 */
public record Caller(String id, Set<String> permissions, int permitsPerSecond, int burstCapacity) {
}
