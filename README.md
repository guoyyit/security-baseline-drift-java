# security-baseline-drift-java

本地安全配置基线核查与漂移检测服务。接收多来源配置快照，依据可版本化的规则集与基线集判定合规状态，输出可追踪、去重的违规发现项，支持规则演进、例外豁免、增量核查与崩溃恢复。全部状态保存在进程内与本地检查点文件中，不依赖外部服务。

## 构建与测试

```bash
mvn compile     # 编译
mvn test        # 运行全部自动化测试
mvn spring-boot:run  # 启动 REST 服务（默认 8080 端口）
```

## 架构

```
api/      DriftController        REST 入口
service/  DriftDetectionService  编排门面：读写锁、增量缓存、检查点提交
          EvaluationCache        有界 LRU 求值缓存
engine/   CheckEngine            纯函数求值（规则 + 基线漂移 + 豁免过滤）
          ScopeResolver          作用域解析、基线继承、豁免冲突仲裁（全程可解释）
store/    SnapshotStore          每来源仅保留最新快照
          RuleSetStore           不可变规则集版本 + 原子当前指针
          BaselineStore          不可变基线集版本 + 原子当前指针
          ExemptionStore         版本化豁免集
          FindingStore           发现项去重与生命周期状态机
          CheckpointStore        本地文件检查点（原子重命名）
model/    不可变领域类型（record）与 Finding 生命周期实体
```

## 一致性语义

### 1. 快照排序（乱序 / 重复 / 迟到）
- 每个来源（`sourceId`）只保留**版本号严格更大**的快照；相等版本视为 `DUPLICATE`，更小版本视为 `OUT_OF_ORDER_OR_LATE`，均被拒绝且不触发重查。
- 因此最终合规判定只取决于各来源**最高版本**的快照，与到达顺序无关。
- 拒绝是原子的（`ConcurrentHashMap.merge`），并发提交同一来源也安全。

### 2. 规则集 / 基线集的版本可见性
- 规则集与基线集均为**不可变版本对象**，发布后存入历史版本表，当前指针通过 `AtomicReference` 整体切换。
- 一次核查在开始时一次性捕获规则版本、基线版本、豁免版本三个引用，求值全程使用这份完整代际，**不会出现字段级混合**。
- 历史版本永久保留（`RuleSetStore.version(n)`），用同一快照 + 同一历史版本重放即可**复现历史结果**；每份 `CheckReport` 与 `Finding` 都记录其所用的规则/基线版本号。

### 3. 作用域、继承与豁免冲突
- 作用域特异性：`EXACT(4) > REGEX(3) > PREFIX(2) > GLOBAL(1)`。
- **规则**：所有作用域匹配的规则都生效（不互相排斥）。
- **基线继承**：最具体的匹配基线获胜，较不具体的匹配基线作为祖先，其属性被继承并被更具体者覆盖（`GLOBAL` 为最终父级）。
- **豁免冲突**：先比较显式 `priority`（高者胜），再比较作用域特异性，最后按 `id` 字典序取小者——结果确定。过期豁免（`expiresAt` 已过）不参与。`ruleId="*"` 表示豁免所有规则。
- 上述每一项决策都写入 `CheckReport.explanations`，全过程可解释。

### 4. 发现项去重与生命周期
- 指纹 = `ruleId|sourceId|attributeKey`，同一指纹永远只有一条发现项。
- 生命周期：`NEW`（首次出现）→ `PERSISTENT`（后续核查仍在）→ `RESOLVED`（违规消失）；`ACKNOWLEDGED` 为人工确认覆盖态；已 `RESOLVED` 的发现项若违规重现则**重开为 NEW**（复用原指纹，不产生新发现项）。
- 风险解除后保持 `RESOLVED`，重复核查**不会重复告警**；基线漂移违规使用合成规则 id `baseline-drift:<baselineId>`，同样进入该生命周期。

### 5. 增量核查与内存上界
- 缓存键 = `sourceId | 快照内容SHA-256 | 规则版本 | 基线版本 | 豁免版本`。快照内容或任一配置代际变化都会自然失效（旧键不再被命中并被 LRU 淘汰），**不会返回过期结果**。
- 缓存命中时违规列表直接复用（内容相同必然相同），但快照版本号等易变元数据按本次运行重新盖戳。
- 缓存为**有界 LRU**（`drift.cache-max-entries`），快照存储每来源仅留最新一份，因此大快照、多来源场景下内存使用有界。

### 6. 崩溃恢复
- 每次状态变更（快照接受、规则/基线/豁免发布、确认操作、显式核查）后，将完整已提交状态序列化为单个 JSON，先写 `state.json.tmp` 再**原子重命名**为 `state.json`，崩溃不会留下部分写入。
- 序号 `sequence` 单调递增，标识最近已提交位置；重启时从该位置整体恢复快照、全部规则/基线历史版本、豁免集与发现项，**不重复生成、不遗漏**发现项。
- 检查点文件损坏时按空状态启动（不致崩溃），已提交的旧文件因原子重命名始终可读。

### 7. 并发一致性
- 变更操作（提交、发布、核查、确认）持**写锁**，查询持**读锁**；任一时刻查询到的都是某个已提交代际的一致视图。
- 求值引擎无状态，输入为不可变版本对象，核查与发布并发时各自看到完整版本。

## 配置项（application.properties）

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `drift.checkpoint-dir` | `${java.io.tmpdir}/drift-checkpoints` | 检查点目录（崩溃恢复） |
| `drift.cache-max-entries` | `1024` | 增量求值缓存最大条目（内存上界） |

## REST API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/drift/snapshots` | 提交配置快照（`sourceId`/`version`/`collectedAt`/`attributes`） |
| POST | `/api/drift/rules` | 发布新规则集版本（整体替换，版本号自增） |
| POST | `/api/drift/baselines` | 发布新基线集版本 |
| POST | `/api/drift/exemptions` | 整体替换豁免集（版本号自增） |
| POST | `/api/drift/checks/{sourceId}` | 对指定来源执行核查 |
| POST | `/api/drift/checks` | 对所有来源执行核查 |
| GET | `/api/drift/findings?status=` | 查询发现项（可按状态过滤） |
| POST | `/api/drift/findings/{fingerprint}/acknowledge` | 人工确认发现项 |

## 测试覆盖

- `SnapshotStoreTest`：乱序、重复、迟到快照的拒绝与最终状态正确性。
- `ScopeResolverTest`：作用域优先级、基线继承、豁免冲突（优先级→特异性→id）、过期豁免、通配豁免。
- `DriftDetectionServiceTest`：规则演进与历史可复现、发现项全生命周期（新建/持续/解除/重开/不重复告警）、人工确认、增量缓存命中与失效、有界缓存淘汰、豁免端到端生效、基线漂移检测、崩溃恢复后继续不重复不遗漏、乱序快照不影响最终合规。
- `ConcurrencyConsistencyTest`：提交/规则发布/基线发布/查询高并发下的状态一致性与最终代际正确性。
- `DriftApiTest`：REST 层端到端冒烟。
