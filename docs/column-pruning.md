# 列裁剪与过滤下推：设计与验收

## 背景

查询只 `SELECT` 少数列时，底层表实现仍计算全部列。以 Linux `processes`
为例：每行要读 `/proc/<pid>/{cmdline,exe,cwd,root,attr/current,io,cgroup}`
等约 9 个文件，其中任何一列未被请求时这些 I/O 都是纯浪费。`file` 表每个
路径执行 lstat+stat+status 三次 stat 族调用；`process_open_sockets` 为建立
inode→pid 映射要遍历每个进程的 `/proc/<pid>/fd` 目录。

## 机制

### 列需求如何到达表实现（基线已有，本方案补全并修正）

- SQLite 在 `xBestIndex` 通过 `sqlite3_index_info.colUsed` 告知本次查询用到
  哪些列（投影、WHERE、JOIN 条件、ORDER BY、聚合参数都算"用到"）。
- osquery 已将其按 idxNum 存入 `VirtualTableContent::colsUsed /
  colsUsedBitsets`，`xFilter` 再拷贝进 `QueryContext`。
- 表实现通过 `QueryContext::isColumnUsed() / isAnyColumnUsed()` 查询某列是否
  被需要，自行跳过对应计算。**未调用这些接口的表行为不变（全列计算），
  不可能算错**——这就是"未声明列依赖时回退全列"的降级路径。

### 本次改动（`osquery/sql/virtual_table.cpp`、`osquery/core/tables.h`）

1. **开关**：`--enable_column_pruning`（默认 `true`，保持基线行为；置
   `false` 时 `QueryContext` 的两个列需求字段都留空，所有 `isColumnUsed`
   族接口返回 true，即全列计算，用于 A/B 对比）。
   注：基线代码已经把 colUsed 传给表（darwin/windows `processes` 等表和
   `test_used_columns_default`、`test_table_results_cache` 等既有测试依赖
   该行为），所以"默认全列"反而是行为回退，不可取。

2. **同表多游标的列需求合并**：SQLite 在执行任何 `xFilter` 之前完成整条
   语句所有游标的 `xBestIndex`，因此子查询/自连接对同一张表的列需求在
   生成行之前已全部就绪。`xFilter` 将**本语句**各游标的列需求取并集传给
   表实现，保证经查询缓存共享的行对所有游标都完整（"不能各算各的"）。
   语句边界用水位线判定：`xBestIndex` 发现上一轮规划后已有 `xFilter`
   执行过，就把当前 idxNum 记为 `planning_start_idx`；`xFilter` 只合并
   `>= planning_start_idx` 的条目，避免把历史语句（规划状态是惰性清理
   的）的需求误并进来。不同表各有 `VirtualTableContent`，**JOIN 下两张
   表的列需求天然分开**，不会退化成并集全算。

3. **异常定位**：`computeColumnValue(column, fn)`（`tables.h`）包装列级
   计算，抛出的异常信息带列名，经 `xFilter` 的表级 catch 上报后能定位到
   具体列。

### 过滤下推

基线结构已具备：`xBestIndex` 把 INDEX/REQUIRED/ADDITIONAL/OPTIMIZED 列的
约束经 `xFilter` 传入 `QueryContext::constraints`，表实现据此少生成行
（`processes` 的 pid、`file` 的 path/directory、`process_open_sockets`
的 pid 均已消费）。关键安全网：osquery **从不设置**
`aConstraintUsage[].omit`，因此 SQLite 在表返回行之后仍会自行复核所有
约束——表不支持某条下推时结果不会多出任何行（测试
`unpushed_constraints_still_filter` 用一个忽略约束的插件验证）。

### 副作用一致性

- `processes` 的 `path`/`on_disk` 是依赖组：`getOnDisk` 会把 path 末尾的
  `" (deleted)"` 剥掉。只要其中任一列被请求，整组计算都执行，保证
  `path` 的值不依赖于 `on_disk` 是否也被请求。
- `file` 的 lstat 永远执行：它同时决定行是否存在，跳过会改变行集而不
  只是列集。`processes` 的 stat/status 同理（行有效性判定），始终读取。
- `process_open_sockets` 的网络命名空间枚举（步骤 2/3）是行生成的
  前提，始终执行；只有 pid/fd 列对应的 `/proc/*/fd` 扫描（步骤 1）按需。

## 各表改动

| 表 | 按需计算的列 | 始终执行 |
|---|---|---|
| `processes` (linux) | cmdline, cgroup_path, cwd, root, label, path+on_disk(依赖组), disk_bytes_read/written | stat+status（行存在性 + 大部分基础列） |
| `file` (posix) | symlink_target_path；stat 组（inode/uid/gid/mode/device/size/block_size/hard_links/atime/mtime/ctime/btime/type/pid_with_namespace/bsd_flags） | lstat（行存在性 + symlink 标志） |
| `process_open_sockets` (linux) | pid, fd（步骤 1 的 `/proc/*/fd` 扫描） | 命名空间枚举与 `/proc/*/net/*` 读取 |

## 验收

### 结果一致性（逐行逐字段）

- gtest `ColumnPruningEndToEndTest`（9 项）：同一进程内对同一查询分别
  以裁剪开/关执行，排序后逐行逐字段比对，覆盖三张表 + count(*)/聚合/
  JOIN/子查询同表合并。
- `tools/compare_pruning.py`：osqueryi 真实二进制 A/B，10 条查询（含
  JOIN、子查询、count、GROUP BY），全部逐行一致。
- 表级 `ProcessesColumnPruningTest`（6 项）：未请求列不在行内出现；
  请求列的值与未裁剪完全一致；空列集（count(*) 场景）行数不变；
  path/on_disk 依赖组；异常信息含列名。
- 机制级 `ColumnPruningTests`（9 项）：开关行为、WHERE 列计入已用、
  未下推约束仍过滤、count(*) 空列集、聚合只计聚合列、**JOIN 两表列
  需求分离**、**子查询同表列需求合并**。

### 性能（生成行数相同；计时区分计划/生成阶段）

计划阶段 = `sqlite3_prepare`（含 xBestIndex），生成阶段 = `sqlite3_step`
循环（含 xFilter/generate/xColumn），各取 5 次最小值。

| 查询 | 行数 | 计划(off/on) | 生成 off | 生成 on | 变化 |
|---|---|---|---|---|---|
| `SELECT pid, name, uid FROM processes` | 92 | 0.008/0.011ms | 13.5ms | 7.7ms | **-43%** |
| `SELECT * FROM processes` | 92 | — | 13.4ms | 13.5ms | 0（全列被请求，符合预期） |
| `SELECT count(*) FROM processes` | 1 | — | 13.0ms | 8.0ms | **-38%** |
| `SELECT local_port, state FROM process_open_sockets` | 402 | — | 11.2ms | 9.7ms | **-13%** |
| `SELECT * FROM process_open_sockets WHERE pid=-1` | 272 | — | 11.6ms | 11.9ms | 0 |
| `SELECT path FROM file WHERE directory='/usr/bin'` | 906 | — | 5.5ms | 2.0ms | **-64%** |
| `SELECT * FROM file WHERE directory='/usr/bin'` | 906 | — | 7.1ms | 7.3ms | 0 |

实际计算的列（strace 实测，裁剪 off → on）：

| 表 | off | on |
|---|---|---|
| processes（85 进程） | 1279 次 /proc 访问（每进程 stat,status,io,cmdline,exe,cwd,root,attr,cgroup 共 9 项） | 346 次（每进程仅 stat,status） |
| file（906 路径） | lstat 906 + stat 1814 + readlink 257 | lstat 906 + stat 2 + readlink 0 |
| process_open_sockets | 473 次 `/proc/*/fd` 目录扫描 | 0 次（net 命名空间读取不变） |

### 回归

- `osquery_sql_tests_virtualtabletests-test` 38/38（含既有缓存/列使用测试）
- `osquery_sql_tests-test` 49/49
- `osquery_tables_system_tests_mergedtests-test` 205/205
- `osquery_core_tests_mergedtests-test` 40/40
- `osquery_worker_ipc_tests_jsonconversions-test` 3/3（列需求经 worker IPC
  序列化的路径）

（`test_processes_disk_io` 及 Augeas/Rpm 用例在本机需 `TMPDIR` 指向磁盘
文件系统与 `TEST_CONF_FILES_DIR` 环境变量，与本次改动无关。）
