# Hostbin

Hostbin is a small self-hosted pastebin inspired by pastes.io. It is built as a single Python application with SQLite persistence and a Docker-first deployment path.

## Features

- Create public or unlisted pastes
- Optional password protection
- Expiration windows from 10 minutes to 1 month, or never
- Burn-after-read pastes
- Raw paste URLs
- Public paste index
- Per-paste delete token link
- SQLite storage in a persistent `/data` volume
- No Python package dependencies

## Run With Docker Compose

```bash
docker compose up -d --build
```

The app will be available at:

```text
http://localhost:8080
```

## Configuration

Set these environment variables in `docker-compose.yml` or your hosting provider.

| Variable | Default | Description |
| --- | --- | --- |
| `APP_NAME` | `Hostbin` | Display name in the UI |
| `BASE_URL` | empty | Public origin used for generated links |
| `DATA_DIR` | `/data` | Directory containing the SQLite database |
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8080` | Port inside the container |
| `MAX_PASTE_BYTES` | `1048576` | Maximum paste body size |
| `GOOGLE_CLIENT_ID` | empty | Optional Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | empty | Optional Google OAuth client secret |
| `GOOGLE_REDIRECT_URI` | empty | Optional OAuth callback URL, defaults to `BASE_URL/auth/google/callback` |

## Google Sign-In

To enable Google sign-in, create a Google OAuth web client and add this authorized redirect URI:

```text
https://your-hostname.example/auth/google/callback
```

Then set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and either `BASE_URL` or `GOOGLE_REDIRECT_URI` in Portainer. The Google button appears only when both client credentials are configured.

## Deploy Notes

For production, set `BASE_URL` to the public HTTPS URL, keep `/data` on persistent storage, and place the service behind a reverse proxy such as Caddy, Traefik, or Nginx.

Example Compose service behind a proxy:

```yaml
services:
  hostbin:
    image: your-registry/hostbin:latest
    restart: unless-stopped
    environment:
      APP_NAME: Hostbin
      BASE_URL: https://paste.example.com
    volumes:
      - hostbin-data:/data
```

## Local Development Without Docker

```bash
python app.py
```

The server listens on `http://127.0.0.1:8080` by default when run locally.
