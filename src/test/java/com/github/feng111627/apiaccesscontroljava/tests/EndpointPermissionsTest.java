package com.github.feng111627.apiaccesscontroljava.tests;

import com.github.feng111627.apiaccesscontroljava.security.EndpointPermissions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 接口权限映射测试。
 */
class EndpointPermissionsTest {

    private static final Logger log = LoggerFactory.getLogger(EndpointPermissionsTest.class);
    private final EndpointPermissions permissions = new EndpointPermissions();

    @Test
    @DisplayName("权限模型: 读接口需 api:read，写接口需 api:write，管理接口需 admin:credentials，其余公开")
    void mappingIsMethodSensitive() {
        assertEquals(Optional.of("api:read"), permissions.requiredPermission("GET", "/api/ping"));
        assertEquals(Optional.of("api:read"), permissions.requiredPermission("GET", "/api/data"));
        assertEquals(Optional.of("api:write"), permissions.requiredPermission("POST", "/api/data"));
        assertEquals(Optional.of("admin:credentials"),
                permissions.requiredPermission("POST", "/admin/credentials/revoke/ak-x"));
        assertTrue(permissions.requiredPermission("GET", "/actuator/health").isEmpty());
        log.info("[权限模型] GET=/api/* -> api:read, POST=/api/data -> api:write, /admin/** -> admin:credentials");
    }
}
