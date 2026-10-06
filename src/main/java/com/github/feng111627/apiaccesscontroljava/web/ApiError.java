package com.github.feng111627.apiaccesscontroljava.web;

/**
 * 统一错误响应体。message 为通用文案，绝不回显凭证原文或其他调用方信息。
 *
 * @param code          机器可读错误码
 * @param message       面向调用方的通用说明
 * @param retryable     是否建议重试
 */
public record ApiError(String code, String message, boolean retryable) {
}
