package com.github.feng111627.apiaccesscontroljava.auth;

import com.github.feng111627.apiaccesscontroljava.model.ApiKey;
import com.github.feng111627.apiaccesscontroljava.model.Caller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * 认证：解析 "keyId.secret" 格式的凭证，识别调用方。
 *
 * 判定优先级（保证结果可解释、互不混淆）：
 * 1. 未携带或格式非法        -> MISSING / INVALID
 * 2. keyId 存在但已吊销      -> REVOKED（优先于过期，吊销是显式动作）
 * 3. keyId 存在但已过期      -> EXPIRED
 * 4. 密钥散列不匹配或不存在  -> INVALID（不区分"id 对密钥错"，避免信息泄露）
 * 5. 全部通过                -> OK
 *
 * 日志只记录 keyId 与 callerId，绝不记录密钥明文。
 */
@Service
public class Authenticator {

    private static final Logger log = LoggerFactory.getLogger(Authenticator.class);

    private final CredentialService credentialService;
    private final CallerRegistry callerRegistry;
    private final Clock clock;

    @org.springframework.beans.factory.annotation.Autowired
    public Authenticator(CredentialService credentialService, CallerRegistry callerRegistry) {
        this(credentialService, callerRegistry, Clock.systemUTC());
    }

    public Authenticator(CredentialService credentialService, CallerRegistry callerRegistry, Clock clock) {
        this.credentialService = credentialService;
        this.callerRegistry = callerRegistry;
        this.clock = clock;
    }

    public AuthResult authenticate(String presentedKey) {
        if (presentedKey == null || presentedKey.isBlank()) {
            return AuthResult.fail(AuthResult.Status.MISSING);
        }
        int dot = presentedKey.indexOf('.');
        if (dot <= 0 || dot == presentedKey.length() - 1) {
            log.info("认证失败: 凭证格式非法");
            return AuthResult.fail(AuthResult.Status.INVALID);
        }
        String keyId = presentedKey.substring(0, dot);
        String secret = presentedKey.substring(dot + 1);
        Instant now = clock.instant();

        Optional<ApiKey> found = credentialService.findByKeyId(keyId);
        if (found.isPresent()) {
            ApiKey key = found.get();
            if (key.status() == ApiKey.KeyStatus.REVOKED) {
                log.info("认证失败: 凭证已吊销, keyId={}", keyId);
                return AuthResult.fail(AuthResult.Status.REVOKED);
            }
            if (!now.isBefore(key.expiresAt())) {
                log.info("认证失败: 凭证已过期, keyId={}, expiredAt={}", keyId, key.expiresAt());
                return AuthResult.fail(AuthResult.Status.EXPIRED);
            }
        }

        Optional<ApiKey> active = credentialService.findActive(keyId, secret, now);
        if (active.isEmpty()) {
            log.info("认证失败: 凭证无效, keyId={}", keyId);
            return AuthResult.fail(AuthResult.Status.INVALID);
        }
        Optional<Caller> caller = callerRegistry.find(active.get().callerId());
        if (caller.isEmpty()) {
            log.warn("认证失败: 凭证指向未知调用方, keyId={}", keyId);
            return AuthResult.fail(AuthResult.Status.INVALID);
        }
        return AuthResult.ok(caller.get(), keyId);
    }
}
