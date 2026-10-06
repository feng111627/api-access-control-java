package com.github.feng111627.apiaccesscontroljava.model;

import java.time.Instant;

/**
 * 凭证记录。只保存密钥的散列，不保存明文。
 */
public record ApiKey(String keyId, String secretHash, String callerId,
                     KeyStatus status, Instant notBefore, Instant expiresAt) {

    public enum KeyStatus {
        ACTIVE, REVOKED
    }
}
