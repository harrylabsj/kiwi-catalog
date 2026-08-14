# 发布与版本管理（releasing）

> 本文档说明 kiwi-catalog 作为 **portfolio release 的 PyPI 消费者** 如何参与
> 发布，以及版本、tag、回滚与安全检查流程。本仓库**不维护独立的发布
> pipeline**，任何本地或 CI 命令默认只做 dry-run，不执行对 PyPI 的真实发布。

## 1. 定位：PyPI 消费者

kiwi-catalog 不是独立发布入口。它是 kiwi（`harrylabsj/kiwi`）portfolio
release 工作流的一个**消费者**：正式版本的构建、签名与上传由 kiwi 的
**受保护发布 workflow** 统一驱动。本仓库只提供包元数据（`pyproject.toml`
`[project]`）与可复现构建产物（wheel/sdist），不持有任何发布入口。

## 2. Trusted Publisher / OIDC 前置条件

- 对 PyPI 的发布使用 **Trusted Publisher（OIDC）**；任何 workflow 中**不得**
  存放长期 PyPI token（如 `pypi_token` / `api_token` / twine 密码）。
- OIDC 的信任关系（trusted publisher 映射、发布方）由 kiwi 的受保护发布
  workflow 统一管理。kiwi-catalog 侧无需也不能自行配置 PyPI 凭据。

## 3. dry-run 默认不发布

- 所有本地构建/发布命令默认以 **dry-run** 执行，只构建并校验产物，不执行
  实际上传：

  ```sh
  uv build
  uv publish --dry-run
  ```

- dry-run 通过后，真实发布只能由 kiwi 的受保护发布 workflow 在满足前置条件时
  触发；任何本地 `uv publish`（非 `--dry-run`）或直接向 PyPI 上传都属于违规
  流程，禁止执行。
- kiwi 的 `portfolio-release.yml` **仅由手动 `workflow_dispatch` 触发**，默认
  即 dry-run（`publish=false`）：构建、校验、签名并上传发布 bundle，但不触碰
  任何 registry。真实发布必须显式 `publish=true` 手动 dispatch。

## 4. 版本、tag 与回滚

### 4.1 版本号

- 版本号唯一来源是 `pyproject.toml` 的 `project.version`（当前 `0.2.2`），
  按语义化版本（SemVer）提升。
- 只改文档/模板、不触碰业务逻辑/公共 API/依赖版本时，不得提升主版本号。

### 4.2 受保护发布（workflow_dispatch，手动触发）

- 正式发布**不由 tag 自动触发**。kiwi 的 `portfolio-release.yml` **仅**
  `workflow_dispatch`，由人工手动 dispatch。
- 真实发布（`publish=true`）时，`ref` 输入必须是**完整 40 位小写 commit SHA**
  （dry-run `publish=false` 才允许命名 ref）；发布 job 由受保护的
  `kiwi-release` 环境（required review）把关。
- 正式发布流程：先手动 dispatch、以完整 40 位 SHA 完成受保护发布；发布完成后
  再打 tag 作为不可变版本标记。本仓库不自行执行真实发布。
- 发布前运行 `uv lock --check`、`uv run --locked python scripts/verify_contract_lock.py`
  与完整测试。

### 4.3 Tag（发布后的不可变标记）

- tag 与版本号一一对应：`v<version>`（如 `v0.1.0`）。
- tag **不是触发器**，仅为已发布 commit 的不可变版本标记；在发布完成后创建，
  不驱动任何自动化。
- tag 必须由受保护发布/契约锁校验通过后推送；推送后不得改写历史，不得
  force-push 已发布 tag。

### 4.4 回滚

- 发现发布缺陷时回滚到上一个已验证的 tag，不在服务器上直接 `git pull`，也不
  修改已发布产物。
- 回滚策略与运维回滚一致（见 `deploy/production.md`）：确认 schema 迁移对旧
  版本透明（迁移只增不改、`user_version` 门），再切换 artifact/镜像。
- PyPI 上已发布版本不可覆写；如确需撤回，走 PyPI 项目运维流程（yank），并在
  kiwi 的发布工作流中记录。
- kiwi 的 `verify_rollback` / `previous_manifest` 输入可对上一个发布 manifest
  做**只读**回滚候选校验（只验证、绝不删除或取消发布任何内容）。

## 5. 安全检查流程

发布/打 tag 前必须满足（与 `SECURITY.md`、`CONTRIBUTING.md` 一致）：

1. 无长期 token / 凭据入库：配置与工作流中不存在 `pypi_token`、`api_token`
   或长期明文 `GITHUB_TOKEN`。
2. 第三方 GitHub Actions 全部固定到**完整 40 位提交 SHA**（如
   `actions/checkout@11bd7190...`），并注释对应版本号；不得使用可变 tag/branch
   引用。
3. 依赖锁定：`uv lock --check` / `uv sync --locked` 通过。
4. 契约校验：`uv run --locked python scripts/verify_contract_lock.py` 通过。
5. 静态检查与测试：`ruff`、`mypy`、`pytest` 全绿。
6. 发布产物不含数据库文件、`.env*`、密钥、缓存或构建中间物。

## 6. 谁可以触发真实发布

- 只有 kiwi 的受保护发布 workflow（受 branch protection / required review
  保护）可以触发对 PyPI 的真实上传；该 workflow **仅由手动 `workflow_dispatch`
  触发**（无 tag 自动触发），真实发布需 `publish=true` 且 `ref` 为完整 40 位
  小写 commit SHA。
- 本仓库维护者负责准备版本号；发布动作统一由该 workflow 完成，本仓库不执行
  真实发布。tag 在发布完成后作为不可变版本标记创建。
