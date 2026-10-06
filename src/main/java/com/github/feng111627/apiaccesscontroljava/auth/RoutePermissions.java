package com.github.feng111627.apiaccesscontroljava.auth;

import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * 接口权限映射：Ant 风格路径模式 -> 所需权限。
 * 未匹配到任何模式的接口默认不需要权限（公开接口）。
 */
@Component
public class RoutePermissions {

    private final AntPathMatcher matcher = new AntPathMatcher();
    private final Map<String, String> patterns = new LinkedHashMap<>();

    public RoutePermissions() {
        // 先精确后通配，LinkedHashMap 保证匹配顺序稳定
        patterns.put("/api/admin/**", "admin:config");
        patterns.put("/api/reports/**", "reports:read");
    }

    /** 返回该路径所需权限；空表示公开接口。 */
    public Optional<String> requiredPermission(String path) {
        return patterns.entrySet().stream()
                .filter(e -> matcher.match(e.getKey(), path))
                .map(Map.Entry::getValue)
                .findFirst();
    }
}
