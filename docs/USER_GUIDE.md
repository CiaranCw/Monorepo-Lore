# Monorepo-Lore 用户使用指南

本指南面向项目组日常开发人员，介绍如何通过 `lore-mono` 登录、同步和提交你有权限的游戏仓库。

## 1. 首次登录

```powershell
lore-mono login --config client.toml --username <你的用户名>
```

按提示输入密码（输入时不显示字符）。

- 登录一次后，会话凭据会安全保存在本地凭据目录中。
- **之后可以直接运行命令，无需重复输入用户名密码。**
- 只有当你主动退出、修改密码，或管理员禁用/调整你的账号后，才需要重新登录。

修改密码：

```powershell
lore-mono password --config client.toml
```

退出登录：

```powershell
lore-mono logout --config client.toml
```

## 2. 查看可见项目与模块

```powershell
# 查看你有权访问的项目
lore-mono project list --config client.toml

# 切换默认项目（只需执行一次）
lore-mono project use Kubee --config client.toml

# 查看当前你在该项目中有权访问的小仓库
lore-mono module list --config client.toml
```

## 3. Clone 全部有权限的小仓库

```powershell
lore-mono clone --all-authorized --config client.toml --root <你的工作目录>
```

- 每个小仓库会被 Clone 到 `<你的工作目录>\<模块名>`。
- 系统会自动切换到各游戏仓库记录的默认分支（如 `master` 或 `main`）。
- 只会 Clone 你有权限的模块；无权限的模块和大仓库根仓库不会出现。

## 4. 查看所有仓库状态与同步更新

```powershell
# 查看所有已授权小仓库的状态
lore-mono status --all --config client.toml --root <你的工作目录>

# 从远端同步全部已授权小仓库
lore-mono sync --all --config client.toml --root <你的工作目录>
```

也可以只针对单个模块操作：

```powershell
lore-mono status <模块名> --config client.toml --root <你的工作目录>
lore-mono sync <模块名> --config client.toml --root <你的工作目录>
```

## 5. 日常修改、批量暂存、Commit 与 Push

当你在多个小仓库中同时修改、新增或删除文件后，只需依次运行：

```powershell
# 1. 批量暂存所有已克隆且有权限的仓库变更
lore-mono stage --all --config client.toml --root <你的工作目录>

# 2. 为每个有暂存变更的仓库分别创建独立提交
lore-mono commit --all --message "feat: 更新玩法配置" --config client.toml --root <你的工作目录>

# 3. 批量推送到远端
lore-mono push --all --config client.toml --root <你的工作目录>
```

说明：

- `lore-mono stage --all` 会扫描每个已授权且已 Clone 的本地仓库，跳过未 Clone 的模块和被忽略的文件（如 `.loreignore` 匹配项）。
- 每个小仓库都会各自生成独立的提交记录，互不混杂。
- 进入某个具体游戏目录后，也可以直接使用原生 Lore 命令（如 `lore status`、`lore stage`、`lore commit`、`lore push`、`lore sync`）。

## 6. 查看提交历史

```powershell
# 查看项目下所有你有权限的小仓库聚合历史
lore-mono history --all --config client.toml

# 查看全部历史页
lore-mono history --all --all-pages --config client.toml

# 查看单个小仓库的完整历史
lore-mono history <模块名> --all-pages --config client.toml

# 查看分支与 Tag
lore-mono refs <模块名> --config client.toml

# 查看单次提交详情
lore-mono show <模块名> <Commit或Revision> --config client.toml
```

## 7. 权限变更后的行为

- **新增授权**：运行 `lore-mono module list` 即可看到新模块，随后可单独 `lore-mono clone <新模块>` 或重新运行 `lore-mono clone --all-authorized`。
- **撤销授权**：服务端即时生效；后续执行 `module list`、`stage --all`、`history --all` 等命令会自动排除已撤权模块，本地旧目录不会再被访问或误提交。
- **修改密码或账号重新启用**：旧登录会话立即失效，需重新运行一次 `lore-mono login`。

## 8. 命令行快速发现与 AI Agent 指引

- 日常命令行参数速查：`lore-mono --help`
- 面向 AI Agent 的完整能力与约束指引：`lore-mono guide`（机器可读清单：`lore-mono guide --json`）

