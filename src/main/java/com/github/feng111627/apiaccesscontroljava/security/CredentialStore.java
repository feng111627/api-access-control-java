package com.github.feng111627.apiaccesscontroljava.security;

import com.github.feng111627.apiaccesscontroljava.domain.Credential;
import com.github.feng111627.apiaccesscontroljava.domain.CredentialStatus;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * 凭证存储：负责凭证的签发、查找、轮换与吊销。
 * <p>
 * 一致性模型：
 * <ul>
 *   <li>所有凭证以不可变 {@link Credential} 快照存放；状态变更 = 用新快照整体替换，
 *       读侧拿到的快照在整个判定过程中不会被改变，因此一次请求看到的凭证要么全旧要么全新，
 *       不会出现"同一凭证时好时坏"。</li>
 *   <li>使用读写锁发布：读路径共享读锁，可并发；轮换/吊销持写锁完成"旧证失效 + 新证生效"，
 *       变更整体对外原子。</li>
 *   <li>重叠窗口：轮换时把旧凭证的逻辑有效期设置为 now + overlapMillis（不复制新 TTL），
 *       窗口内新旧凭证都为 ACTIVE；窗口结束旧证惰性转为 EXPIRED，立即失效。</li>
 *   <li>存储中只保留密钥的 SHA-256 摘要；比较用常量时间比对，避免时序侧信道。</li>
 * </ul>
 */
@Component
public class CredentialStore {

    private static final int SECRET_BYTES = 32;
    private static final String KEY_PREFIX = "ak-";

    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();

    /** keyId -> 凭证快照。读多写少，写操作在写锁内替换快照。 */
    private final java.util.Map<String, Credential> byKeyId = new java.util.HashMap<>();
    /** 调用方 -> 其全部凭证 keyId（含历史凭证）。 */
    private final java.util.Map<String, List<String>> keyIdsByCaller = new java.util.HashMap<>();

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public CredentialStore(Clock clock) {
        this.clock = clock;
    }

    /** 签发结果：plaintextSecret 只在签发/轮换的响应中出现这一次。 */
    public record IssuedCredential(String keyId, String callerId, String plaintextSecret,
                                   long issuedAt, Long expiresAt) {
    }

    /**
     * 为调用方签发新凭证（不影响其已有凭证）。
     *
     * @param ttlMillis 有效期；null 表示不过期
     */
    public IssuedCredential issue(String callerId, Long ttlMillis) {
        return insert(callerId, newKeyId(), newSecret(), ttlMillis, clock.millis());
    }

    /**
     * 引导/测试用：以指定 keyId 与密钥原文写入一张 ACTIVE 凭证。
     * 仅用于本地演示种子数据，业务路径应使用 {@link #issue} / {@link #rotate}。
     */
    public IssuedCredential seedCredential(String callerId, String keyId,
                                           String plaintextSecret, Long ttlMillis) {
        return insert(callerId, keyId, plaintextSecret, ttlMillis, clock.millis());
    }

    private IssuedCredential insert(String callerId, String keyId, String plaintextSecret,
                                    Long ttlMillis, long now) {
        Credential credential = new Credential(
                keyId, callerId, sha256Hex(plaintextSecret.getBytes(StandardCharsets.UTF_8)),
                CredentialStatus.ACTIVE,
                now, ttlMillis == null ? null : now + ttlMillis);

        lock.writeLock().lock();
        try {
            byKeyId.put(keyId, credential);
            keyIdsByCaller.computeIfAbsent(callerId, k -> new ArrayList<>()).add(keyId);
        } finally {
            lock.writeLock().unlock();
        }
        return new IssuedCredential(keyId, callerId, plaintextSecret, now, credential.expiresAt());
    }

    /**
     * 轮换调用方当前有效的凭证。
     * <p>
     * 新凭证立即生效；旧的有效凭证保留至 {@code now + overlapMillis}
     * （若旧凭证本身更早到期则以更早时间为准），窗口结束自动失效。
     *
     * @param ttlMillis      新凭证有效期；null 表示不过期
     * @param overlapMillis  新旧凭证重叠窗口（毫秒）
     * @return 新凭证（密钥原文只返回一次）
     */
    public IssuedCredential rotate(String callerId, Long ttlMillis, long overlapMillis) {
        if (overlapMillis < 0) {
            throw new IllegalArgumentException("overlapMillis must not be negative");
        }
        long now = clock.millis();
        lock.writeLock().lock();
        try {
            List<String> ids = keyIdsByCaller.get(callerId);
            if (ids == null || ids.isEmpty()) {
                throw new IllegalStateException("no credential to rotate for caller: " + callerId);
            }
            // 1) 让当前仍有效的旧凭证在重叠窗口结束时失效：逻辑到期，状态随即过期
            for (String oldKeyId : ids) {
                Credential old = byKeyId.get(oldKeyId);
                if (old != null && old.status() == CredentialStatus.ACTIVE && isEffective(old, now)) {
                    long graceEnd = now + overlapMillis;
                    long effectiveEnd = old.expiresAt() == null ? graceEnd : Math.min(old.expiresAt(), graceEnd);
                    byKeyId.put(oldKeyId, new Credential(old.keyId(), old.callerId(), old.secretHash(),
                            old.status(), old.issuedAt(), effectiveEnd));
                }
            }
            // 2) 新凭证在同一把写锁内生效：旧证窗口失效与新证生效整体原子
            String keyId = newKeyId();
            String plaintext = newSecret();
            Credential fresh = new Credential(keyId, callerId, sha256Hex(plaintext.getBytes(StandardCharsets.UTF_8)),
                    CredentialStatus.ACTIVE, now, ttlMillis == null ? null : now + ttlMillis);
            byKeyId.put(keyId, fresh);
            ids.add(keyId);
            return new IssuedCredential(keyId, callerId, plaintext, now, fresh.expiresAt());
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * 立即吊销凭证。不存在或已处于终态（轮换/过期/吊销）时返回 false。
     * 吊销对后续请求立即生效。
     */
    public boolean revoke(String keyId) {
        lock.writeLock().lock();
        try {
            Credential current = byKeyId.get(keyId);
            if (current == null || current.status() != CredentialStatus.ACTIVE) {
                return false;
            }
            byKeyId.put(keyId, current.withStatus(CredentialStatus.REVOKED));
            return true;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * 按密钥原文定位当前有效的凭证。
     * <p>
     * 摘要比较采用常量时间逻辑（{@link MessageDigest#isEqual}），
     * 不在错误信息中区分"keyId 不存在/已吊销/已过期"，统一返回 empty。
     */
    public Optional<Credential> findActiveBySecret(String plaintextSecret) {
        if (plaintextSecret == null || plaintextSecret.isBlank()) {
            return Optional.empty();
        }
        byte[] presented = sha256(plaintextSecret.getBytes(StandardCharsets.UTF_8));

        // 第一阶段：读锁内取一致快照做判定；若命中但已过期，记录待惰性标记的 keyId
        String expiredKeyId = null;
        lock.readLock().lock();
        try {
            long now = clock.millis();
            for (Credential candidate : byKeyId.values()) {
                if (candidate.status() != CredentialStatus.ACTIVE) {
                    continue;
                }
                if (!MessageDigest.isEqual(presented, HexFormat.of().parseHex(candidate.secretHash()))) {
                    continue;
                }
                if (!isEffective(candidate, now)) {
                    expiredKeyId = candidate.keyId();
                    break;
                }
                return Optional.of(candidate);
            }
        } finally {
            lock.readLock().unlock();
        }

        // 第二阶段：释放读锁后再上写锁完成惰性过期标记（锁不升级，避免配平错误）
        if (expiredKeyId != null) {
            lock.writeLock().lock();
            try {
                Credential current = byKeyId.get(expiredKeyId);
                if (current != null && current.status() == CredentialStatus.ACTIVE
                        && !isEffective(current, clock.millis())) {
                    byKeyId.put(expiredKeyId, current.withStatus(CredentialStatus.EXPIRED));
                }
            } finally {
                lock.writeLock().unlock();
            }
        }
        return Optional.empty();
    }

    /** 按 keyId 查找凭证快照（任意状态），供管理面/审计使用。 */
    public Optional<Credential> findByKeyId(String keyId) {
        lock.readLock().lock();
        try {
            return Optional.ofNullable(byKeyId.get(keyId));
        } finally {
            lock.readLock().unlock();
        }
    }

    private static boolean isEffective(Credential c, long now) {
        return c.expiresAt() == null || now < c.expiresAt();
    }

    private String newKeyId() {
        byte[] bytes = new byte[8];
        secureRandom.nextBytes(bytes);
        return KEY_PREFIX + HexFormat.of().formatHex(bytes);
    }

    private String newSecret() {
        byte[] bytes = new byte[SECRET_BYTES];
        secureRandom.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    private static String sha256Hex(byte[] input) {
        return HexFormat.of().formatHex(sha256(input));
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
