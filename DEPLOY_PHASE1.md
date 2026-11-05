# ARTEX Phase 1 deployment

## GitHub-hosted Runner (no VPS required)

The workflow `.github/workflows/phase1-runner.yml` starts PostgreSQL and ARTEX on a temporary GitHub-hosted Ubuntu runner. It builds and embeds the frontend, starts the backend on localhost, then checks:
- `GET /api/health`
- `GET /api/auth/status` (proves PostgreSQL access)
- `GET /` (embedded frontend)

It runs on pushes to the Phase 1 branch and on pull requests targeting main. Open Actions and select **Phase 1 Runner deployment** to inspect logs.

The runner is temporary. ARTEX is available only during that job, has no stable public URL, and its process and database are discarded when the job ends. This is a real online startup/integration check, not persistent hosting. It requires no SSH credentials and does not test external targets or invoke a live LLM.

## GHCR image and optional VPS

The workflow `.github/workflows/phase1-image.yml` publishes amd64 and arm64 images to GHCR on each push to the Phase 1 branch:
- `ghcr.io/javeleyqaq/artex:phase1-latest`
- `ghcr.io/javeleyqaq/artex:phase1-<commit-sha>`

For a long-running instance, use a separate Linux Docker host. Copy `docker-compose.phase1.yml`, `skills/`, and `.env.phase1.example` to a dedicated directory. Copy the example to `.env.phase1` and set a long alphanumeric PostgreSQL password. Log in to GHCR on the host if the package is private, then run:

```bash
docker compose -p artex-phase1 --env-file .env.phase1 -f docker-compose.phase1.yml pull
docker compose -p artex-phase1 --env-file .env.phase1 -f docker-compose.phase1.yml up -d
```

The isolated stack uses port 18787, loopback-only proxy port 18788, a dedicated named PostgreSQL volume, and `data-phase1/`. It does not mount or expose the normal ARTEX data directory or ports.

### Optional GitHub Actions SSH deployment

Add these repository secrets: `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_PATH`, `DEPLOY_SSH_KEY`, and `DEPLOY_KNOWN_HOSTS`. `DEPLOY_PORT` is optional (defaults to 22). Prepare Docker/Compose and `.env.phase1` on the server. If the GHCR package is private, log in on the server with a token that can pull packages.

Set repository variable `DEPLOY_PHASE1=true` to let feature-branch pushes deploy after publishing. Without that variable, the workflow only publishes the image and never connects to a server. Do not put private keys or tokens in source files or chat.
