package com.github.feng111627.apiaccesscontroljava.auth;

import com.github.feng111627.apiaccesscontroljava.model.Caller;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 调用方注册表：线程安全的内存实现。
 */
@Component
public class CallerRegistry {

    private final ConcurrentHashMap<String, Caller> callers = new ConcurrentHashMap<>();

    public void register(Caller caller) {
        callers.put(caller.id(), caller);
    }

    public Optional<Caller> find(String callerId) {
        return Optional.ofNullable(callers.get(callerId));
    }
}
