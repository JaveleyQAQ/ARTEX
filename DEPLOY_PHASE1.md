# ARTEX Phase 1 独立验收部署

本部署使用 PR #2 分支构建的镜像，不合并 PR、不修改 `main`，并与现有 ARTEX 实例隔离。

## 1. 从 GitHub Actions 构建镜像

1. 打开仓库 Actions → **Phase 1 container**。
2. 选择 **Run workflow**，分支选择 `feat/vulnerability-intelligence-foundation`。
3. 镜像标签使用 `phase1-latest`（默认值）。
4. 等待构建完成。工作流会发布 amd64/arm64 镜像：
   - `ghcr.io/javeleyqaq/artex:phase1-latest`
   - `ghcr.io/javeleyqaq/artex:phase1-<commit-sha>`

镜像构建使用该次运行选定分支的代码。请在 Actions 运行摘要中核对 source commit。

## 2. 在独立 Docker 主机启动

将仓库中的 `docker-compose.yml`、`docker-compose.phase1.yml`、`skills/` 和 `.env.phase1.example` 放到独立部署目录。复制并编辑环境文件：

```bash
cp .env.phase1.example .env.phase1
# 修改 POSTGRES_PASSWORD，建议使用随机长密码
```

如果 GHCR 镜像为私有包，在部署主机先登录（使用有 read:packages 权限的 GitHub PAT）：

```bash
echo '<GHCR_READ_TOKEN>' | docker login ghcr.io -u '<GITHUB_USERNAME>' --password-stdin
```

启动：

```bash
docker compose -p artex-phase1 --env-file .env.phase1 \
  -f docker-compose.yml -f docker-compose.phase1.yml pull artex

docker compose -p artex-phase1 --env-file .env.phase1 \
  -f docker-compose.yml -f docker-compose.phase1.yml up -d
```

访问 `http://<服务器地址>:18787`。首次进入按 ARTEX 页面引导设置管理员密码。**不要把 18787 暴露到公网；建议先通过 SSH 隧道或反向代理访问，并配置 HTTPS。** 代理流量端口 18788 仅绑定到 localhost。

## 3. 隔离与回滚

- PostgreSQL 使用独立 Compose project volume（`artex-phase1_pgdata`）。
- ARTEX 文件数据写入部署目录的 `data-phase1/`，不复用原有 `data/`。
- Web 入口使用 18787，不占用现有 8787。
- 停止验收环境：使用相同的 `-p`、`--env-file` 和 `-f` 参数执行 `down`。不要添加 `-v`，以保留验收数据。
- 回滚应用版本：将 `.env.phase1` 中的 `ARTEX_TAG` 改为上一次验证过的不可变 `phase1-<commit-sha>`，再执行 `pull` 和 `up -d`。

## 4. GitHub Actions SSH 自动部署

在 GitHub 仓库 Settings → Secrets and variables → Actions 中添加以下 Repository secrets：

| Secret | 内容 |
| --- | --- |
| `DEPLOY_HOST` | 测试服务器公网 IP 或域名 |
| `DEPLOY_PORT` | SSH 端口；可不设，默认 22 |
| `DEPLOY_USER` | SSH 登录用户 |
| `DEPLOY_PATH` | 独立部署目录，例如 `/opt/artex-phase1` |
| `DEPLOY_SSH_KEY` | 对应用户的 SSH 私钥（不要提交到仓库） |
| `DEPLOY_KNOWN_HOSTS` | 预先核验过的 SSH host key 行 |

服务器需预先安装 Docker Engine 和 Docker Compose，并在部署目录创建好 `.env.phase1`（参考 `.env.phase1.example`）。若 GHCR 镜像为私有包，还需在服务器执行一次 `docker login ghcr.io`，使用有 `read:packages` 权限的 PAT。不要把 SSH 私钥或 PAT 发到聊天中。

配置完成后，在 Actions → **Phase 1 container** 运行工作流，选择 `feat/vulnerability-intelligence-foundation`，勾选 `deploy`。工作流先构建并推送镜像，再通过 SSH 更新独立的 `artex-phase1` Compose stack；部署时使用不可变的 commit tag。未勾选 `deploy` 时只构建和推送镜像，不连接任何服务器。

当前尚未配置可验证的部署主机信息，所以我没有向未知主机发起部署。
