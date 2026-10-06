package com.github.feng111627.apiaccesscontroljava.domain;

import java.util.Set;

/**
 * 调用方（API 使用方）。一个调用方可拥有若干凭证并持有一组权限。
 *
 * @param id          调用方标识
 * @param displayName 展示名
 * @param permissions 权限集合（如 api:read、api:write、admin:credentials）
 */
public record Caller(String id, String displayName, Set<String> permissions) {
}
