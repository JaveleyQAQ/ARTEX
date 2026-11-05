# GitHub Codespaces

该开发容器为 ARTEX 提供 Go 1.26.3、Node.js 22 和独立 PostgreSQL 17。

创建 Codespace 后会自动安装前端依赖，并通过仓库根目录的 `dev.sh` 启动：
- Web UI：转发端口 5173
- Go API：转发端口 8787
- 流量代理：容器内 8788

端口默认保持私有。需要体验时，在 Codespaces 的 Ports 面板中打开 5173。
PostgreSQL 数据保存在 Codespaces Docker volume 中；删除 Codespace/volume 前请先备份。
LLM API Key 不写入仓库；需要模型能力时，在 Codespaces 的 Secrets 中配置相应环境变量并重启服务。

该环境仅用于开发和隔离靶场/CTF 演示，不是 24×7 生产部署。
