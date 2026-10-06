package com.github.feng111627.apiaccesscontroljava.security;

import com.github.feng111627.apiaccesscontroljava.domain.Caller;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 调用方注册表：维护调用方与其权限集合。
 * {@link Caller} 本身为不可变记录，注册即整体替换，读到的权限集合在一次判定内稳定。
 */
@Component
public class CallerRegistry {

    private final ConcurrentHashMap<String, Caller> callers = new ConcurrentHashMap<>();

    public void register(Caller caller) {
        if (caller == null || caller.id() == null) {
            throw new IllegalArgumentException("caller and its id must not be null");
        }
        callers.put(caller.id(), caller);
    }

    public Optional<Caller> find(String callerId) {
        return Optional.ofNullable(callers.get(callerId));
    }

    public Set<String> permissionsOf(String callerId) {
        Caller caller = callers.get(callerId);
        return caller == null ? Set.of() : caller.permissions();
    }
}
