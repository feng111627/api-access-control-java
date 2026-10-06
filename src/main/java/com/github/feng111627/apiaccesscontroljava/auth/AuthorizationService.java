package com.github.feng111627.apiaccesscontroljava.auth;

import com.github.feng111627.apiaccesscontroljava.model.Caller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 授权：判断调用方是否拥有目标接口要求的权限。
 * 权限模型为扁平字符串集合，精确匹配；"*" 为通配超级权限。
 */
@Service
public class AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationService.class);

    public boolean isAllowed(Caller caller, String requiredPermission) {
        boolean allowed = caller.permissions().contains(requiredPermission)
                || caller.permissions().contains("*");
        if (!allowed) {
            log.info("授权拒绝: callerId={}, 所需权限={}", caller.id(), requiredPermission);
        }
        return allowed;
    }
}
