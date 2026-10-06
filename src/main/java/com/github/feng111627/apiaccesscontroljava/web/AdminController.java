package com.github.feng111627.apiaccesscontroljava.web;

import com.github.feng111627.apiaccesscontroljava.security.CredentialStore;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 凭证生命周期管理接口（需 admin:credentials 权限）。
 * 新密钥原文只在本响应中返回一次，服务端不再保存原文。
 */
@RestController
@RequestMapping("/admin/credentials")
public class AdminController {

    private final CredentialStore credentialStore;

    public AdminController(CredentialStore credentialStore) {
        this.credentialStore = credentialStore;
    }

    /** 为调用方签发新凭证（可选 TTL 毫秒，不传表示不过期）。 */
    @PostMapping("/issue/{callerId}")
    public Map<String, Object> issue(@PathVariable String callerId,
                                     @RequestParam(required = false) Long ttlMillis) {
        CredentialStore.IssuedCredential issued = credentialStore.issue(callerId, ttlMillis);
        return toBody(issued);
    }

    /** 轮换调用方凭证，旧凭证在 overlapMillis 内继续有效。 */
    @PostMapping("/rotate/{callerId}")
    public Map<String, Object> rotate(@PathVariable String callerId,
                                      @RequestParam(required = false) Long ttlMillis,
                                      @RequestParam(defaultValue = "60000") long overlapMillis) {
        CredentialStore.IssuedCredential issued = credentialStore.rotate(callerId, ttlMillis, overlapMillis);
        Map<String, Object> body = toBody(issued);
        body.put("overlapMillis", overlapMillis);
        return body;
    }

    /** 立即吊销凭证。 */
    @PostMapping("/revoke/{keyId}")
    public Map<String, Object> revoke(@PathVariable String keyId) {
        boolean revoked = credentialStore.revoke(keyId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("keyId", keyId);
        body.put("revoked", revoked);
        return body;
    }

    private Map<String, Object> toBody(CredentialStore.IssuedCredential issued) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("keyId", issued.keyId());
        body.put("callerId", issued.callerId());
        body.put("credential", issued.plaintextSecret());
        body.put("issuedAt", issued.issuedAt());
        body.put("expiresAt", issued.expiresAt());
        return body;
    }
}
