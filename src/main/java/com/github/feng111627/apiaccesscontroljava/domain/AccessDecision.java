package com.github.feng111627.apiaccesscontroljava.domain;

/**
 * 一次访问判定的完整结果，可解释、可审计。
 *
 * @param code     判定码
 * @param callerId 命中的调用方（仅认证成功时有值）
 * @param keyId    命中的凭证标识（仅认证成功时有值，可安全记录）
 * @param detail   面向日志/运维的说明（不含密钥原文与其他调用方信息）
 */
public record AccessDecision(AccessDecisionCode code, String callerId, String keyId, String detail) {

    public static AccessDecision allow(String callerId, String keyId) {
        return new AccessDecision(AccessDecisionCode.ALLOW, callerId, keyId, "allowed");
    }
}
