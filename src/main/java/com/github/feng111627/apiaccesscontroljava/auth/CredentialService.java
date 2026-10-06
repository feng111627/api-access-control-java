package com.github.feng111627.apiaccesscontroljava.auth;

import com.github.feng111627.apiaccesscontroljava.model.ApiKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 凭证生命周期管理：签发、轮换（重叠窗口）、吊销、查询。
 *
 * 并发与一致性约定：
 * - 存储使用 ConcurrentHashMap，单条记录的读取是原子的；
 * - 吊销/轮换通过整体替换不可变记录（compute 原子更新）完成，
 *   任何一次请求只会读到替换前或替换后的某一个完整版本，
 *   因此同一凭证不会出现"时好时坏"的判断；
 * - 只保存密钥散列，明文仅在签发时返回一次，日志只记录 keyId。
 */
@Service
public class CredentialService {

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);

    private final ConcurrentHashMap<String, ApiKey> keysByKeyId = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final Clock clock;

    public CredentialService() {
        this(Clock.systemUTC());
    }

    public CredentialService(Clock clock) {
        this.clock = clock;
    }

    /** 签发结果：明文密钥仅此一次可见。 */
    public record IssuedKey(ApiKey key, String plaintextSecret) {

        /** 请求头中呈现的完整凭证串：keyId.secret */
        public String presented() {
            return key.keyId() + "." + plaintextSecret;
        }
    }

    /** 为调用方签发新凭证。 */
    public IssuedKey issue(String callerId, Duration ttl) {
        String keyId = "key_" + randomToken(8);
        String secret = randomToken(32);
        Instant now = clock.instant();
        ApiKey key = new ApiKey(keyId, hash(secret), callerId,
                ApiKey.KeyStatus.ACTIVE, now, now.plus(ttl));
        keysByKeyId.put(keyId, key);
        log.info("凭证已签发: keyId={}, callerId={}, expiresAt={}", keyId, callerId, key.expiresAt());
        return new IssuedKey(key, secret);
    }

    /**
     * 轮换：签发新凭证，同时把该调用方现有有效凭证的过期时间
     * 收紧到 now + overlap（重叠窗口内新旧同时有效，窗口外旧凭证失效）。
     */
    public IssuedKey rotate(String callerId, Duration ttl, Duration overlap) {
        Instant now = clock.instant();
        Instant overlapEnd = now.plus(overlap);
        keysByKeyId.replaceAll((keyId, key) -> {
            if (key.callerId().equals(callerId)
                    && key.status() == ApiKey.KeyStatus.ACTIVE
                    && key.expiresAt().isAfter(overlapEnd)) {
                log.info("轮换收紧旧凭证: keyId={}, callerId={}, 新过期时间={}", keyId, callerId, overlapEnd);
                return new ApiKey(key.keyId(), key.secretHash(), key.callerId(),
                        key.status(), key.notBefore(), overlapEnd);
            }
            return key;
        });
        IssuedKey issued = issue(callerId, ttl);
        log.info("凭证已轮换: callerId={}, newKeyId={}, overlap={}", callerId, issued.key().keyId(), overlap);
        return issued;
    }

    /** 吊销：立即失效，后续请求一律判定为已吊销。 */
    public void revoke(String keyId) {
        keysByKeyId.computeIfPresent(keyId, (id, key) -> {
            log.info("凭证已吊销: keyId={}, callerId={}", id, key.callerId());
            return new ApiKey(key.keyId(), key.secretHash(), key.callerId(),
                    ApiKey.KeyStatus.REVOKED, key.notBefore(), key.expiresAt());
        });
    }

    /**
     * 按 keyId + 明文密钥查询有效凭证。
     * 密钥不匹配按"不存在"处理，避免在日志/响应中区分"id 对但密钥错"。
     */
    public Optional<ApiKey> findActive(String keyId, String secret, Instant now) {
        ApiKey key = keysByKeyId.get(keyId);
        if (key == null || !MessageDigest.isEqual(
                key.secretHash().getBytes(StandardCharsets.UTF_8),
                hash(secret).getBytes(StandardCharsets.UTF_8))) {
            return Optional.empty();
        }
        return Optional.of(key);
    }

    /** 仅按 keyId 查询（不做密钥校验），用于认证时区分吊销/过期。 */
    public Optional<ApiKey> findByKeyId(String keyId) {
        return Optional.ofNullable(keysByKeyId.get(keyId));
    }

    public static String hash(String secret) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private String randomToken(int bytes) {
        byte[] buf = new byte[bytes];
        random.nextBytes(buf);
        return HexFormat.of().formatHex(buf);
    }
}
