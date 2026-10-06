package com.github.feng111627.apiaccesscontroljava.domain;

/**
 * 凭证生命周期状态。
 */
public enum CredentialStatus {
    /** 有效：可用于鉴权（含轮换重叠窗口内的旧凭证）。 */
    ACTIVE,
    /** 已轮换作废：重叠窗口结束后自动标记，立即失效。 */
    ROTATED,
    /** 已过期：超过 expiresAt 后惰性标记，立即失效。 */
    EXPIRED,
    /** 已吊销：管理员主动吊销，立即失效。 */
    REVOKED
}
