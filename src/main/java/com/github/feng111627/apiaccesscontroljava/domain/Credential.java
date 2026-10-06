package com.github.feng111627.apiaccesscontroljava.domain;

/**
 * API 凭证。密钥原文只在创建/轮换时返回一次，存储层只保存 SHA-256 摘要。
 *
 * @param keyId       凭证标识（可暴露，用于定位与日志）
 * @param callerId    所属调用方
 * @param secretHash  密钥的 SHA-256 摘要（hex）
 * @param status      生命周期状态
 * @param issuedAt    签发时间（epoch millis）
 * @param expiresAt   到期时间（epoch millis）；null 表示不过期
 */
public record Credential(String keyId, String callerId, String secretHash,
                         CredentialStatus status, long issuedAt, Long expiresAt) {

    public Credential withStatus(CredentialStatus newStatus) {
        return new Credential(keyId, callerId, secretHash, newStatus, issuedAt, expiresAt);
    }
}
