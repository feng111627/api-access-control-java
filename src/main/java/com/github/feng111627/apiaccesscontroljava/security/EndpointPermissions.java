package com.github.feng111627.apiaccesscontroljava.security;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;

/**
 * 接口 → 所需权限的映射表。未登记的接口视为公开接口（不做访问控制）。
 * <p>
 * 权限模型：
 * <ul>
 *   <li>GET  /api/ping ：api:read</li>
 *   <li>GET  /api/data ：api:read</li>
 *   <li>POST /api/data ：api:write</li>
 *   <li>/admin/**     ：admin:credentials</li>
 * </ul>
 */
@Component
public class EndpointPermissions {

    private static final Map<String, String> EXACT_RULES = Map.of(
            "GET /api/ping", "api:read",
            "GET /api/data", "api:read",
            "POST /api/data", "api:write"
    );

    /** 返回该 method+path 所需权限；公开接口返回 empty。 */
    public Optional<String> requiredPermission(String method, String path) {
        if (path != null && path.startsWith("/admin/")) {
            return Optional.of("admin:credentials");
        }
        return Optional.ofNullable(EXACT_RULES.get(method + " " + path));
    }
}
