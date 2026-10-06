package com.github.feng111627.apiaccesscontroljava.auth;

import com.github.feng111627.apiaccesscontroljava.model.Caller;

/**
 * 认证结果：区分 未携带 / 无效 / 已吊销 / 已过期 / 成功。
 */
public record AuthResult(Status status, Caller caller, String keyId) {

    public enum Status {
        OK, MISSING, INVALID, REVOKED, EXPIRED
    }

    public static AuthResult ok(Caller caller, String keyId) {
        return new AuthResult(Status.OK, caller, keyId);
    }

    public static AuthResult fail(Status status) {
        return new AuthResult(status, null, null);
    }
}
