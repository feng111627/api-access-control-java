package com.github.feng111627.apiaccesscontroljava.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 用于演示权限分层的业务接口。
 */
@RestController
@RequestMapping("/api")
public class DemoController {

    @GetMapping("/ping")
    public Map<String, Object> ping(HttpServletRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("service", "api-access-control");
        body.put("caller", request.getAttribute(AccessControlFilter.CALLER_ATTRIBUTE));
        body.put("message", "pong");
        return body;
    }

    @GetMapping("/data")
    public Map<String, Object> readData(HttpServletRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("caller", request.getAttribute(AccessControlFilter.CALLER_ATTRIBUTE));
        body.put("data", "sample-read-payload");
        return body;
    }

    @PostMapping("/data")
    public Map<String, Object> writeData(HttpServletRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("caller", request.getAttribute(AccessControlFilter.CALLER_ATTRIBUTE));
        body.put("accepted", true);
        return body;
    }
}
