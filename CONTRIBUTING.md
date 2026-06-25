# 贡献指南

## 开始开发

项目使用 Go 1.21 或更高版本。

```bash
git clone https://github.com/DHKun/dddd.git
cd dddd
go test ./...
go build ./...
```

从 `main` 创建聚焦单一问题的分支：

```bash
git checkout -b fix/issue-number-short-description
```

## 缺陷修复

缺陷报告需要包含版本、操作系统、脱敏命令、完整日志和最小复现步骤。修复提交应包含能够覆盖根因的回归测试。

## 提交前检查

```bash
gofmt -w .
go vet ./...
go test ./...
go build ./...
```

PR 描述需要说明改动、根因、用户影响、验证命令和关联 Issue。每个 PR 保持单一主题，便于审查、回滚和发布。

## 安全与授权

dddd 面向合法授权的企业安全建设和安全测试。测试、日志与复现材料应使用自建靶场或已授权目标，并清除真实凭据、Token、客户信息和内部网络数据。
