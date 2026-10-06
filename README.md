# API 访问控制（Spring Boot）

在普通业务接口前增加一层按调用方区分的 **认证 → 授权 → 配额** 访问控制，
重点解决并发请求与凭证轮换/吊销并发时判定结果的**一致、可解释**，以及失败时**不泄露秘密**。

## 1. 权限模型

### 1.1 调用方、凭证与权限
- **调用方（Caller）**：API 使用方，由 `callerId` 标识；持有一组权限字符串（如 `api:read`、`api:write`、`admin:credentials`）。
- **凭证（Credential）**：调用方持有的密钥。请求通过 `Authorization: Bearer <密钥原文>` 识别。
  - 服务端**只存 SHA-256 摘要**，密钥原文仅在签发/轮换响应中返回一次。
  - 摘要比对使用常量时间比较（`MessageDigest.isEqual`），降低时序侧信道风险。
- **判定顺序**：先认证（你是谁），再授权（你能否访问该接口），最后配额（你此刻能否请求）。
  这样可以把性质不同的失败严格区分开。

### 1.2 接口所需权限

| 方法 & 路径 | 所需权限 | 说明 |
| --- | --- | --- |
| `GET /api/ping` | `api:read` | 演示只读 |
| `GET /api/data` | `api:read` | 读数据 |
| `POST /api/data` | `api:write` | 写数据 |
| `/admin/**` | `admin:credentials` | 凭证管理面 |
| 其他路径 | （无需凭证） | 未登记的视为公开接口 |

### 1.3 五种判定结果（严格区分，可解释）

| 判定码 | HTTP | 含义 | 可重试 |
| --- | --- | --- | --- |
| `ALLOW` | 200 | 认证、授权、配额均通过 | — |
| `MISSING_CREDENTIAL` | 401 | 根本没带凭证（含 `Bearer ` 后为空） | 否 |
| `INVALID_CREDENTIAL` | 401 | 带了但无法识别 / 已吊销 / 已过期（**三者响应完全相同**，不泄露具体原因） | 否 |
| `FORBIDDEN` | 403 | 凭证有效、身份已识别，但无目标接口权限 | 否 |
| `RATE_LIMITED` | 429 | 身份与权限没问题，但调用方此刻配额耗尽 | 是，响应带 `Retry-After`（秒） |

错误响应统一为：
```json
{"code":"rate_limited","message":"Rate limit exceeded. Retry after the suggested delay.","retryable":true}
```

**防泄密**：错误文案与日志都不回显密钥原文；认证失败时不提及任何调用方；
日志只记录调用方**自身** `callerId`、`keyId`（非敏感标识）与判定码。
keyId 仅在认证成功后才出现在日志中。

## 2. 限额规则

按**调用方**维度实施独立**令牌桶**（`TokenBucket`）：

- `capacity`：桶容量，即允许瞬间打满的**突发上限**。新桶初始为满。
- `refillPerSecond`：匀速补充速率（持续吞吐）。
- 每次请求尝试消耗 1 个令牌：
  - 够 → 放行并**恰好**消耗 1 个；
  - 不够 → 返回 `RATE_LIMITED`，**本次不消耗令牌**（不漏计后续配额）。
- `Retry-After` = 补出下一个令牌所需时间（向上取整为秒，至少 1s）。

**并发安全**：桶状态 `(令牌数, 上次补充时间戳)` 作为不可变快照，
"补充 → 扣减 → 提交"通过一次 CAS 完成；竞争失败的线程拿最新快照重试。
因此 N 个并发请求最多消耗 N 个令牌，**不超发**；被拒请求不扣令牌，**不漏计**。
单测用 100 线程抢 50 令牌、多调用方各 100 线程等场景验证（见 `TokenBucketTest`、`QuotaServiceTest`）。

演示配额：`demo-app` 容量 3 / 每秒补 1（容易触发限流）；`partner-service` 20 / 每秒补 5；`admin-tool` 10 / 每秒补 2。

## 3. 凭证生命周期

```
 签发(issue)                 轮换(rotate)
 ┌────────┐   过期/吊销/轮换  ┌──────────┐  overlap 结束   ┌──────────┐
 │ ACTIVE │ ───────────────▶ │ (旧证)   │ ──────────────▶ │ EXPIRED  │
 └────────┘                  │ ACTIVE   │                  └──────────┘
                             └──────────┘
   吊销(revoke) 任意时刻 ────────────────────────────────▶ ┌──────────┐
                                                           │ REVOKED  │
                                                           └──────────┘
```

- **签发 `issue`**：生成随机 keyId + 32 字节随机密钥，存摘要。
- **轮换 `rotate(ttl, overlapMillis)`**：
  - 新凭证在**同一把写锁内**与旧凭证的"窗口失效时间"一起原子发布；
  - 旧凭证在 `now + overlapMillis` 内保持有效（若旧证自身更早到期，以更早者为准），窗口结束立即失效；
  - 因此轮换发布后，并发请求对旧证要么全部在窗口内成功、要么全部在窗口外失败，**不会同一凭证时好时坏**。
- **吊销 `revoke`**：持写锁用 `REVOKED` 快照整体替换，**立即**对后续所有请求生效；重复吊销 / 吊销不存在的凭证幂等返回 `false`。
- **过期**：以不可变快照上的 `expiresAt` 判定，`now >= expiresAt` 立即失效并惰性把状态标记为 `EXPIRED`。

**一致性基础**：所有凭证/调用方数据均为不可变快照；凭证存储用读写锁发布
（读路径共享读锁、可并发，变更持写锁整体替换）。一次请求基于拿到的那一版快照完成全部判定，
中途不受变更影响，从机制上避免了"判定撕裂"。并发自洽由
`CredentialRotationConcurrencyTest`（窗口内 32 并发旧证全部成功；吊销后 64 并发全部失败）验证。

### 3.1 管理接口（需 `admin:credentials`）

| 接口 | 作用 |
| --- | --- |
| `POST /admin/credentials/issue/{callerId}?ttlMillis=` | 签发新凭证（ttl 可空 = 不过期） |
| `POST /admin/credentials/rotate/{callerId}?ttlMillis=&overlapMillis=60000` | 轮换，旧证重叠窗口内仍可用 |
| `POST /admin/credentials/revoke/{keyId}` | 立即吊销 |

> 响应里的 `credential` 字段即密钥原文，**只返回这一次**，请立即保存。

## 4. 本地验证

### 4.1 环境
JDK 21+、Maven（离线可用，依赖已在本地仓库）。

### 4.2 启动
```bash
mvn spring-boot:run
# server.port=0 表示随机端口，看日志 "Tomcat started on port xxxxx"
```
启动时自动播种 3 个调用方与固定演示凭证（仅本地演示用，见 `DataInitializer`）：

| callerId | 密钥（演示） | 权限 | 配额(容量/每秒) |
| --- | --- | --- | --- |
| `demo-app` | `demo-secret-0001-please-rotate-locally` | `api:read` | 3 / 1 |
| `partner-service` | `partner-secret-0001-please-rotate-locally` | `api:read`,`api:write` | 20 / 5 |
| `admin-tool` | `admin-secret-0001-please-rotate-locally` | `api:read`,`admin:credentials` | 10 / 2 |

### 4.3 手工验证（把 PORT 换成启动端口）
```bash
PORT=xxxxx
# 没带凭证 -> 401 missing_credential
curl -i localhost:$PORT/api/ping
# 错误凭证 -> 401 invalid_credential（与缺凭证不同码）
curl -i -H 'Authorization: Bearer wrong' localhost:$PORT/api/ping
# 正常读 -> 200
curl -i -H 'Authorization: Bearer demo-secret-0001-please-rotate-locally' localhost:$PORT/api/ping
# 只读方越权写 -> 403 forbidden
curl -i -X POST -H 'Authorization: Bearer demo-secret-0001-please-rotate-locally' localhost:$PORT/api/data
# 突发限流：连发 4 次，前 3 个 200，之后 429 + Retry-After
for i in $(seq 1 4); do curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Authorization: Bearer demo-secret-0001-please-rotate-locally' localhost:$PORT/api/ping; done
# 轮换（5s 重叠窗口），观察窗口内新旧皆可、窗口后旧证 401
RESP=$(curl -s -X POST -H 'Authorization: Bearer admin-secret-0001-please-rotate-locally' \
  "$PORT/admin/credentials/rotate/demo-app?overlapMillis=5000")
NEW=$(echo "$RESP" | sed -n 's/.*"credential":"\([^"]*\)".*/\1/p')
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $NEW" localhost:$PORT/api/ping
```

### 4.4 运行单元测试
```bash
mvn test
```
- 共 29 个用例，控制台与 `target/test-logs/test-output.log` 会打印带 `[模块-场景]` 前缀的覆盖日志，
  如 `[凭证-轮换]`、`[配额-并发]`、`[判定-无权限]`、`[HTTP-限流]`，可直观看出覆盖的业务与各用例情况。
- 测试与报告对应关系：

| 测试类 | 覆盖业务 |
| --- | --- |
| `TokenBucketTest` | 突发上限、匀速补充、重试提示、**并发不超发/不漏计** |
| `QuotaServiceTest` | 按调用方隔离、默认桶、多调用方并发不超发 |
| `CredentialStoreTest` | 签发认证、TTL 过期边界、吊销即时幂等、轮换重叠窗口、早到期边界 |
| `CredentialRotationConcurrencyTest` | 轮换窗口并发自洽、吊销后并发立即全部失败 |
| `AccessControlServiceTest` | 五类判定、吊销/过期即时翻转、限流与无权限区分、按调用方隔离、**判定不泄密** |
| `EndpointPermissionsTest` | 接口→权限映射、方法敏感、公开接口 |
| `AccessControlHttpIntegrationTest` | 401/403/429/200 状态码、`WWW-Authenticate`/`Retry-After`、响应不泄密、管理面保护 |

## 5. 代码结构

```
domain/   Caller / Credential(+Status) / AccessDecision(+Code) / TokenBucket
security/ CredentialStore（签发/轮换/吊销/查找，读写锁+快照）
          CallerRegistry（权限） / EndpointPermissions（接口→权限）
          QuotaService（每调用方令牌桶） / AccessControlService（三步判定门面）
web/      AccessControlFilter（判定→HTTP 映射 + 安全日志）
          DemoController / AdminController
config/   ClockConfig（可替换时钟） / DataInitializer（演示种子数据）
```
