package com.github.feng111627.apiaccesscontroljava.security;

import com.github.feng111627.apiaccesscontroljava.domain.AccessDecision;
import com.github.feng111627.apiaccesscontroljava.domain.AccessDecisionCode;
import com.github.feng111627.apiaccesscontroljava.domain.Caller;
import com.github.feng111627.apiaccesscontroljava.domain.Credential;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * 访问控制门面：串联 认证(凭证) → 授权(权限) → 配额 三步判定。
 * <p>
 * 每一步都基于不可变快照（{@link Credential}、{@link Caller}）做决策：
 * 凭证轮换/吊销在另一个原子边界内发布，进行中的请求始终拿到某一版完整快照，
 * 因此凭证变更与并发请求之间结果自洽，不会出现同一凭证时好时坏。
 * <p>
 * 失败被刻意区分成三类，且都不回显凭证或其他调用方信息：
 * MISSING_CREDENTIAL（没带）、INVALID_CREDENTIAL（带了但无效/过期/被吊销）、
 * FORBIDDEN（有效但无权）、RATE_LIMITED（有权但超配额，可重试）。
 */
@Component
public class AccessControlService {

    private final CredentialStore credentialStore;
    private final CallerRegistry callerRegistry;
    private final QuotaService quotaService;
    private final EndpointPermissions endpointPermissions;

    public AccessControlService(CredentialStore credentialStore, CallerRegistry callerRegistry,
                                QuotaService quotaService, EndpointPermissions endpointPermissions) {
        this.credentialStore = credentialStore;
        this.callerRegistry = callerRegistry;
        this.quotaService = quotaService;
        this.endpointPermissions = endpointPermissions;
    }

    /**
     * 对一次请求做完整判定。
     *
     * @param method          HTTP 方法
     * @param path            请求路径
     * @param credentialHint  Authorization 头中 Bearer 后的原始凭证（可能为 null/空白）
     */
    public AccessDecision decide(String method, String path, String credentialHint) {
        Optional<String> required = endpointPermissions.requiredPermission(method, path);
        if (required.isEmpty()) {
            // 公开接口：不做任何访问控制
            return AccessDecision.allow(null, null);
        }

        // 1) 认证：区分"未携带"与"携带但无效"
        if (credentialHint == null || credentialHint.isBlank()) {
            return new AccessDecision(AccessDecisionCode.MISSING_CREDENTIAL, null, null,
                    "no credential presented for " + method + " " + path);
        }
        Optional<Credential> matched = credentialStore.findActiveBySecret(credentialHint.trim());
        if (matched.isEmpty()) {
            // 不区分不存在/被吊销/已过期，避免给调用方枚举凭证的线索
            return new AccessDecision(AccessDecisionCode.INVALID_CREDENTIAL, null, null,
                    "credential rejected (unknown, revoked or expired)");
        }
        Credential credential = matched.get();

        // 2) 授权：基于不可变调用方快照判断权限
        Optional<Caller> caller = callerRegistry.find(credential.callerId());
        if (caller.isEmpty()) {
            // 凭证有效但主体已不存在：按无效凭证处理，绝不透露主体信息
            return new AccessDecision(AccessDecisionCode.INVALID_CREDENTIAL, null, null,
                    "credential principal unavailable");
        }
        if (!caller.get().permissions().contains(required.get())) {
            return new AccessDecision(AccessDecisionCode.FORBIDDEN, caller.get().id(),
                    credential.keyId(), "missing required permission: " + required.get());
        }

        // 3) 配额：原子扣减，失败明确标记可重试
        if (!quotaService.tryAcquire(caller.get().id())) {
            return new AccessDecision(AccessDecisionCode.RATE_LIMITED, caller.get().id(),
                    credential.keyId(), "quota exhausted; retry after suggested delay");
        }

        return AccessDecision.allow(caller.get().id(), credential.keyId());
    }
}
