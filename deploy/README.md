# Deploying Warden with Docker Compose

This deployment runs the dashboard behind Nginx and keeps the API private on the Compose network. Nginx proxies `/v1/*` and `/docs` to the API, so the dashboard and API share one public origin.

## Start

1. Install Docker Engine and the Docker Compose plugin on the host.
2. Copy `.env.example` to `.env` in this directory.
3. Set `WARDEN_API_KEY` to a unique, high-entropy secret. Never use the development key in production.
4. Run `docker compose --env-file .env -f deploy/docker-compose.yml up -d --build` from the repository root.
5. Open `http://YOUR_HOST:8080`; API docs are at `/docs`.

## Operations

- Inspect status: `docker compose --env-file deploy/.env -f deploy/docker-compose.yml ps`
- View logs: `docker compose --env-file deploy/.env -f deploy/docker-compose.yml logs -f`
- Stop: `docker compose --env-file deploy/.env -f deploy/docker-compose.yml down`
- Back up the local data volume before upgrades: `docker run --rm -v warden_warden-data:/data -v ${PWD}:/backup alpine tar czf /backup/warden-backup.tgz /data`

## Database note

This Compose deployment persists the current JSON repository on a named Docker volume. It is suitable for a single-node internal deployment. Multi-instance or high-availability production use needs a dedicated Postgres migration because the current repository API is synchronous; do not mount the same JSON file into multiple API replicas.
