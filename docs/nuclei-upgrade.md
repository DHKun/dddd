# Nuclei 升级与模板兼容基线

## 当前基线

- dddd 内嵌 Nuclei v3.3.8。
- 正式支持环境为 Linux amd64、Go 1.21 与最新稳定版。
- 内置 POC 数量为 2405，来源包含历史 Nuclei 模板和项目自维护模板。
- `common/callnuclei` 通过 `common/nucleiadapter` 调用 Nuclei 公开 SDK。

截至 2026-06-25，官方最新引擎为 [v3.9.0](https://github.com/projectdiscovery/nuclei/releases/tag/v3.9.0)，官方最新模板为 [v10.4.5](https://github.com/projectdiscovery/nuclei-templates/releases/tag/v10.4.5)。

## Go 1.21 升级上限

| 版本 | Go 要求 | 结论 |
| --- | --- | --- |
| v3.1.8 | Go 1.21 | 历史基线 |
| [v3.3.8](https://github.com/projectdiscovery/nuclei/releases/tag/v3.3.8) | Go 1.21.0 | 当前基线 |
| v3.3.9 | Go 1.22.2 | 超出当前兼容线 |
| v3.9.0 | Go 1.25.7 | 进入后续平台升级评估 |

v3.3.8 是 Go 1.21 可承载的最高 v3.3 版本。该版本提供公开 SDK、`fs.FS` Catalog、结果 callback 和线程安全执行入口。

## dddd 定制面

本地 v3.3.8 在公开 SDK 上保留以下 dddd 行为：

- 根据每个目标的 Workflow 映射选择 POC。
- 同时加载内嵌 POC 与外部 POC，外部同名模板具有优先级。
- `--external-poc-only` 提供外部规则独占模式。
- Nuclei 结果进入 HTML 报告和 GoPoc 调度。
- 多段 HTTP 请求与响应进入审计数据包。
- Nuclei MySQL dialer 使用隔离网络名，保持 GoPoc 数据库连接生命周期。
- 模板名称、Tags、严重程度和排除标签筛选保持稳定。

## 分阶段升级路径

1. 已建立模板兼容回归集，覆盖多段 raw、动态 extractor、Tags 和 DSL 函数。
2. 已升级至 v3.3.8，并通过公开 SDK 适配层替换 `pkg/exportrunner` 调用。
3. 已实现磁盘模板与内嵌 `fs.FS` 模板的组合加载和同名模板优先级。
4. 已按 Workflow 选择结果对目标分组，通过 SDK 执行每组模板。
5. 已移植结果 callback、审计数据包和 MySQL dialer 隔离。
6. 由 Linux Go 1.21 与 stable CI 持续验证全量测试、race 测试和构建。
7. 后续分批同步模板，每批模板独立通过解析、编译和最小靶场门禁。

## 模板同步门禁

每批候选模板需要通过：

- YAML 严格解析。
- Nuclei 模板编译。
- Workflow 中的文件名、模板 ID 或 Tags 映射。
- 外部模板覆盖内置同名模板。
- Linux Go 1.21 自动化测试。
- 授权本地靶场的请求链和 matcher 验证。

模板集与引擎保持独立版本记录。引擎升级先建立稳定执行层，模板更新随后分批进入。
