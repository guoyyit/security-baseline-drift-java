# security-baseline-drift-java

本地安全配置基线核查与漂移检测服务。接收多来源的配置快照，依据可版本化的
规则集与基线集判定合规状态，输出可追踪的违规发现项，支持规则演进、例外豁免、
增量核查与崩溃恢复。配置快照通过进程内调用或 REST 提交，不依赖外部服务。

## 构建与测试

```bash
mvn compile     # 编译
mvn test        # 运行全部自动化测试
mvn spring-boot:run  # 本地启动（默认端口 8080）
```

## 核心概念

| 概念 | 说明 |
| --- | --- |
| `ConfigSnapshot` | 配置快照：`sourceId` + 单调递增 `version` + `collectedAt` + 扁平键值 `configs`，可携带 `groups` 用于作用域匹配 |
| `RuleSetVersion` | 不可变的规则集版本；规则 = 作用域 + 配置键 + 运算符 + 期望值 + 严重级 |
| `BaselineSetVersion` | 不可变的基线集版本；基线条目 = 作用域 + 配置键 + 期望值，支持继承 |
| `Exemption` | 例外豁免：规则/键 + 作用域 + 截止时间 + 审批人，过期自动失效 |
| `Finding` | 违规发现项，按指纹 `sourceId|ruleId|configKey` 去重，具有完整生命周期 |

## 一致性语义

### 快照顺序
每个来源只保留**版本号最大**的快照。重复、乱序、迟到的快照
（`version <= 当前版本`）被幂等拒绝（`DUPLICATE_OR_STALE`），不触发日志写入
与重新核查，最终合规判定永远等于按最新状态计算的结果。

### 版本化规则/基线
- 规则集与基线集的每个版本都是**完全物化的不可变对象**，通过原子引用切换。
- 一次核查在开始处捕获一次版本引用，因此始终看到**某一个完整版本**，
  绝不会出现字段级混合。
- 历史版本保留在 `version(n)` 中，可用旧版本重放同一快照复现历史结果
  （见 `RuleEvolutionTest`）。

### 作用域与冲突优先级
作用域三级：`SOURCE(3) > GROUP(2) > GLOBAL(1)`。

- **基线继承**：同一键的多个匹配条目中，作用域更具体者生效；同级冲突按
  `priority` 显式优先级、再按 `updatedAtMillis` 较新者裁定。
- **豁免冲突**：多条有效豁免匹配同一违规时，同样按作用域具体度、再按
  `createdAt` 较新者裁定；过期豁免不参与。
- 每次裁定都把全部候选与获胜原因写入违规的 `explanation` 字段，全过程可解释。

### 发现项生命周期
```
NEW --(再次核查仍违规)--> OPEN --(人工确认)--> ACKNOWLEDGED
 |                        |                        |
 |--(豁免生效)--> SUPPRESSED --(豁免移除/过期, 仍违规)--> OPEN
 |                        |
 +--(不再违规)--> RESOLVED --(违规复现)--> OPEN（同一指纹重开，不新建）
```
- 同一指纹只存在一条发现项；解除后风险复现是**重开**而非重复告警。
- 解除后的合规核查不会再次告警（状态保持 `RESOLVED`）。

### 增量核查
核查结果按 `(sourceId, snapshotVersion, ruleSetVersion, baselineVersion,
exemptionVersion, 内容哈希)` 缓存；任一版本号变化即失效。缓存为访问序 LRU，
容量上限由 `drift.eval-cache-max-size` 控制，大快照场景内存有界。

### 崩溃恢复
- 所有变更先写**预写日志**（`[长度][CRC32][JSON]` 帧，追加后 fsync）再应用。
- 一次核查的全部发现项变迁合并为**一条** `EvaluationCommitted` 记录原子落盘，
  不会出现部分写入；崩溃导致的撕裂尾记录在打开时检测并截断。
- 恢复时重放日志重建已提交状态，再按每来源"最近一次已提交的核查位置"
  （快照/规则/基线/豁免四元组版本）精确对账：只有未提交过核查的来源会被补算，
  既不重复生成也不遗漏发现项，评估 id 单调延续不归零。

### 并发
所有写操作（快照、规则、基线、豁免、确认）经单一写锁串行化；
查询持读锁，看到的永远是某次已提交变更**之前或之后**的完整状态，而非中间态。

## 配置项（`application.properties`）

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `drift.journal-dir` | `data` | 预写日志目录（自动创建） |
| `drift.eval-cache-max-size` | `1024` | 增量核查 LRU 缓存上限 |
| `drift.evaluate-on-rule-update` | `true` | 规则/基线发布后是否立即全量重核 |

## REST API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/snapshots` | 提交配置快照（重复/乱序幂等拒绝） |
| POST | `/api/rulesets` | 发布规则集新版本 |
| POST | `/api/baselines` | 发布基线集新版本 |
| POST | `/api/exemptions` | 新增豁免 |
| DELETE | `/api/exemptions/{id}` | 移除豁免 |
| POST | `/api/findings/{fingerprint}/ack?operator=...` | 人工确认发现项 |
| GET | `/api/findings?sourceId=...` | 查询发现项（可按来源过滤） |
| GET | `/api/findings/{fingerprint}` | 查询单条发现项 |

## 测试覆盖

`src/test/java/.../tests/` 下 27 个用例覆盖任务要求的全部场景：

- `SnapshotOrderingTest` — 乱序、重复、迟到快照
- `RuleEvolutionTest` — 规则演进、完整版本可见性、历史版本复现
- `BaselineInheritanceTest` — 配置继承与作用域冲突裁定、可解释性
- `ExemptionConflictTest` — 豁免冲突、过期豁免、豁免移除
- `FindingLifecycleTest` — 新建/持续/确认/解除/重开全生命周期与去重
- `IncrementalEvaluationTest` — 增量核查、缓存失效、LRU 内存上界
- `RecoveryTest` — 重启恢复、撕裂写截断、评估 id 延续、幂等对账
- `ConcurrencyTest` — 快照/规则/基线/查询并发下的一致性
