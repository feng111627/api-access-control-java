# API 访问控制（按调用方鉴权 + 限额）

在 Spring Boot 服务上以过滤器形式提供按调用方区分权限和配额的访问控制，
保证并发请求与凭证变更下判定结果一致、可解释。

## 权限模型

- **调用方（Caller）**：`id` + 权限集合（扁平字符串，精确匹配，`*` 为超级权限）+ 限额参数。
- **接口权限映射（RoutePermissions）**：Ant 风格路径模式 → 所需权限。
  未匹配到的 `/api/**` 路径视为公开接口，不需要凭证。当前内置：
  - `/api/reports/**` → `reports:read`
  - `/api/admin/**` → `admin:config`
- **判定顺序**（`AccessControlFilter`）：认证 → 授权 → 限额，逐级短路，结果可解释：

| 场景 | 状态码 | 响应 code | 说明 |
|---|---|---|---|
| 未携带凭证 | 401 | `CREDENTIAL_MISSING` | 与无权限明确区分 |
| 凭证无效/格式非法 | 401 | `CREDENTIAL_INVALID` | 不区分"id 对密钥错"，不泄露内部状态 |
| 凭证已吊销 | 401 | `CREDENTIAL_REVOKED` | 吊销优先于过期判定 |
| 凭证已过期 | 401 | `CREDENTIAL_EXPIRED` | |
| 凭证有效但无权限 | 403 | `PERMISSION_DENIED` | |
| 触发限额 | 429 | `RATE_LIMITED` | 带 `Retry-After` 响应头，可重试 |
| 通过 | 200 | — | |

**不泄露约定**：日志与响应只出现 `keyId` / `callerId`，绝不出现凭证明文；
存储只保存密钥的 SHA-256 散列，明文仅在签发时返回一次。

## 限额规则

- 每个调用方一个**令牌桶**：容量 = `burstCapacity`，补充速率 = `permitsPerSecond`。
- 取令牌的"补充-判断-扣减"在同一个 `synchronized` 临界区内完成，
  突发高并发下**不超发、不漏计**（有 200 并发抢 50 容量的精确断言测试）。
- 被限流时返回 `Retry-After`：按当前速率攒够一个令牌所需秒数（向上取整，至少 1 秒）。
- 不同调用方的桶互相隔离。

## 凭证生命周期

凭证格式：`keyId.secret`，通过请求头 `X-Api-Key` 携带。

1. **签发（issue）**：生成随机 keyId 与密钥，只存散列，设定过期时间。
2. **轮换（rotate）**：签发新凭证，同时把该调用方现有有效凭证的过期时间
   收紧到 `now + overlap`——**重叠窗口内新旧凭证同时有效**，窗口结束后旧凭证自动失效。
3. **吊销（revoke）**：立即生效。存储用 `ConcurrentHashMap`，吊销/轮换通过
   原子替换不可变记录完成，任何一次请求只会读到替换前或替换后的完整版本，
   同一凭证不会"时好时坏"。
4. **过期**：到达 `expiresAt` 即失效，判定为 `CREDENTIAL_EXPIRED`。

## 本地验证

```bash
# 运行全部单测（30 个用例，日志会打印每个用例覆盖的业务点）
mvn test

# 启动服务（启动日志会打印一次演示凭证，仅此一次）
mvn spring-boot:run
```

启动后用演示凭证验证（以下 `$KEY` 为启动日志中 `caller-report` 的凭证）：

```bash
curl -s localhost:8080/api/public/hello                       # 公开接口, 200
curl -s localhost:8080/api/reports/summary                    # 401 CREDENTIAL_MISSING
curl -s -H "X-Api-Key: bad" localhost:8080/api/reports/summary  # 401 CREDENTIAL_INVALID
curl -s -H "X-Api-Key: $KEY" localhost:8080/api/reports/summary # 200
curl -s -H "X-Api-Key: $KEY" localhost:8080/api/admin/config    # 403 PERMISSION_DENIED
# 快速连续请求超过突发容量后 -> 429 RATE_LIMITED + Retry-After
```

## 测试覆盖

| 测试类 | 覆盖内容 |
|---|---|
| `CredentialServiceTest` | 签发只存散列、轮换重叠窗口、旧凭证过期收紧、吊销立即生效、错误密钥按不存在处理、过期边界、并发轮换/吊销/读取无撕裂 |
| `AuthenticatorTest` | 未携带/格式非法/无效/吊销/过期/成功分级、吊销优先于过期、轮换窗口内新旧均有效、未知调用方不泄露 |
| `RateLimiterTest` | 突发容量、重试提示、按速率补充、调用方隔离、200 并发不超发不漏计 |
| `AccessControlFilterTest` | 公开接口、401 分级、403 与 401 区分、429 + Retry-After、响应不泄露明文、吊销立即生效、轮换窗口端到端 |
