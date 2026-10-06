package com.github.feng111627.apiaccesscontroljava.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 演示接口：不同接口要求不同权限。
 */
@RestController
public class DemoController {

    @GetMapping("/api/public/hello")
    public Map<String, String> hello() {
        return Map.of("message", "hello, this endpoint is public");
    }

    @GetMapping("/api/reports/summary")
    public Map<String, String> reportSummary() {
        return Map.of("report", "summary");
    }

    @GetMapping("/api/admin/config")
    public Map<String, String> adminConfig() {
        return Map.of("config", "admin-only");
    }
}
