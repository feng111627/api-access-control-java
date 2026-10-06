package com.github.feng111627.apiaccesscontroljava.config;

import com.github.feng111627.apiaccesscontroljava.domain.Caller;
import com.github.feng111627.apiaccesscontroljava.security.CallerRegistry;
import com.github.feng111627.apiaccesscontroljava.security.CredentialStore;
import com.github.feng111627.apiaccesscontroljava.security.QuotaService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

/**
 * 本地演示数据：三个调用方、分层权限与令牌桶配额，并各播种一张固定凭证。
 * <p>
 * 固定凭证仅用于本地/测试，方便文档与脚本复现；生产应通过管理接口动态签发。
 */
@Configuration
public class DataInitializer {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    public static final String DEMO_CALLER = "demo-app";
    public static final String PARTNER_CALLER = "partner-service";
    public static final String ADMIN_CALLER = "admin-tool";

    // 演示密钥（本地种子数据，非真实生产密钥）
    public static final String DEMO_SECRET = "demo-secret-0001-please-rotate-locally";
    public static final String PARTNER_SECRET = "partner-secret-0001-please-rotate-locally";
    public static final String ADMIN_SECRET = "admin-secret-0001-please-rotate-locally";

    @Bean
    public ApplicationRunner seedData(CallerRegistry callers, CredentialStore credentials,
                                      QuotaService quotas) {
        return args -> {
            // 调用方与权限：demo 只读；partner 可读写；admin 管凭证（也可读）
            callers.register(new Caller(DEMO_CALLER, "Demo Application", Set.of("api:read")));
            callers.register(new Caller(PARTNER_CALLER, "Partner Service",
                    Set.of("api:read", "api:write")));
            callers.register(new Caller(ADMIN_CALLER, "Administration Tool",
                    Set.of("api:read", "admin:credentials")));

            // 配额：demo 较紧（便于演示限流），partner 宽松，admin 中等
            quotas.configure(DEMO_CALLER, 3.0d, 1.0d);
            quotas.configure(PARTNER_CALLER, 20.0d, 5.0d);
            quotas.configure(ADMIN_CALLER, 10.0d, 2.0d);

            // 固定演示凭证，均不过期（过期/轮换流程可通过管理接口或测试触发）
            credentials.seedCredential(DEMO_CALLER, "ak-demo-0001", DEMO_SECRET, null);
            credentials.seedCredential(PARTNER_CALLER, "ak-partner-0001", PARTNER_SECRET, null);
            credentials.seedCredential(ADMIN_CALLER, "ak-admin-0001", ADMIN_SECRET, null);

            log.info("seeded demo callers and credentials (see README for local usage)");
        };
    }
}
