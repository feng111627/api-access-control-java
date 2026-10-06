package com.github.feng111627.apiaccesscontroljava.tests;

import com.github.feng111627.apiaccesscontroljava.config.DataInitializer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * HTTP 端到端集成测试：验证四类判定到状态码/响应头/响应体的映射，
 * 以及响应体绝不回显密钥原文或其他调用方信息。
 */
@SpringBootTest
@AutoConfigureMockMvc
class AccessControlHttpIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(AccessControlHttpIntegrationTest.class);

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("HTTP-缺凭证: 401 + WWW-Authenticate + missing_credential 错误体")
    void missingCredentialReturns401() throws Exception {
        mockMvc.perform(get("/api/ping"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"))
                .andExpect(jsonPath("$.code").value("missing_credential"))
                .andExpect(jsonPath("$.retryable").value(false));
        log.info("[HTTP-缺凭证] 401 missing_credential，带 WWW-Authenticate: Bearer");
    }

    @Test
    @DisplayName("HTTP-无效凭证: 401 invalid_credential，与缺凭证错误码不同，文案不细分原因")
    void invalidCredentialReturns401() throws Exception {
        mockMvc.perform(get("/api/ping").header(HttpHeaders.AUTHORIZATION, "Bearer nope-nope-nope"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("invalid_credential"))
                .andExpect(jsonPath("$.retryable").value(false));
        log.info("[HTTP-无效凭证] 401 invalid_credential，不区分不存在/吊销/过期");
    }

    @Test
    @DisplayName("HTTP-无权限: 有效凭证但越权写 -> 403 forbidden，与 401 区分")
    void forbiddenReturns403() throws Exception {
        mockMvc.perform(post("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + DataInitializer.DEMO_SECRET))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("forbidden"))
                .andExpect(jsonPath("$.retryable").value(false));
        log.info("[HTTP-无权限] demo-app 写数据 -> 403 forbidden");
    }

    @Test
    @DisplayName("HTTP-放行: 有权限时 200，响应只包含调用方自身信息")
    void allowedReturns200() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/ping")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + DataInitializer.PARTNER_SECRET))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.caller").value("partner-service"))
                .andReturn();
        String body = result.getResponse().getContentAsString();
        assertFalse(body.contains(DataInitializer.PARTNER_SECRET), "响应体不得包含密钥原文");
        assertFalse(body.contains("demo-app"), "响应体不得泄露其他调用方信息");
        log.info("[HTTP-放行] 200 响应仅含调用方自身标识，无密钥、无其他调用方");
    }

    @Test
    @DisplayName("HTTP-限流: demo 桶容量 3，第 4 次请求 429 + Retry-After + retryable=true")
    void rateLimitedReturns429WithRetryAfter() throws Exception {
        // demo-app 容量为 3 的新进程桶；这里独占使用，连发 4 次
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(get("/api/ping")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + DataInitializer.DEMO_SECRET))
                    .andExpect(status().isOk());
        }
        mockMvc.perform(get("/api/ping")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + DataInitializer.DEMO_SECRET))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists(HttpHeaders.RETRY_AFTER))
                .andExpect(jsonPath("$.code").value("rate_limited"))
                .andExpect(jsonPath("$.retryable").value(true));
        log.info("[HTTP-限流] 突发 4 次（容量3）后 -> 429 rate_limited，带 Retry-After 且标记可重试");
    }

    @Test
    @DisplayName("HTTP-管理面: 无 admin 权限调用管理接口被 403 拒绝")
    void adminEndpointRequiresAdminPermission() throws Exception {
        mockMvc.perform(post("/admin/credentials/revoke/ak-x")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + DataInitializer.DEMO_SECRET))
                .andExpect(status().isForbidden());
        log.info("[HTTP-管理面] 非 admin 调用方访问 /admin/** -> 403");
    }
}
