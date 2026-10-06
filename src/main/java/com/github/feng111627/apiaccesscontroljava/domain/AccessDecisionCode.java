package com.github.feng111627.apiaccesscontroljava.domain;

/**
 * 访问判定结果。四类结果严格区分，便于响应、日志与统计解释。
 */
public enum AccessDecisionCode {
    /** 放行。 */
    ALLOW,
    /** 未携带凭证。 */
    MISSING_CREDENTIAL,
    /** 凭证无法识别、状态非有效或已过期（认证失败）。 */
    INVALID_CREDENTIAL,
    /** 认证通过但调用方无目标接口权限（授权失败）。 */
    FORBIDDEN,
    /** 认证与授权均通过，但调用方配额已耗尽。 */
    RATE_LIMITED
}
