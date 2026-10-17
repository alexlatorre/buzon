# --- Build stage: compiler toolchain only here, for better-sqlite3 if no prebuilt binary fits ---
FROM node:24-alpine AS build

WORKDIR /app
RUN apk add --no-cache python3 make g++
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# --- Runtime stage: no compilers, no npm install, unprivileged user ---
FROM node:24-alpine

WORKDIR /app
ENV NODE_ENV=production

COPY --from=build /app/node_modules ./node_modules
COPY package.json server.js config.js db.js ./
COPY db/ ./db/
COPY public/ ./public/
COPY scripts/healthcheck.js scripts/backup.js ./scripts/

# Create data directory for volume mount, owned by the unprivileged node user
# (existing host volumes may need: chown -R 1000:1000 /path/to/data)
RUN mkdir -p /app/data /app/certs && chown -R node:node /app/data /app/certs

# HTTPS port (plain HTTP with TLS=off behind a reverse proxy)
EXPOSE 4000

# Data volume — mount here for persistent storage (DB + uploaded files)
VOLUME ["/app/data"]

# SSL certs — mount your Let's Encrypt certs here:
#   -v /path/to/fullchain.pem:/app/certs/fullchain.pem
#   -v /path/to/privkey.pem:/app/certs/privkey.pem
# The container runs as uid 1000 (node): privkey.pem must be readable by that user.
# Unreadable or invalid certs stop the server; if none are mounted it starts in HTTP mode.
VOLUME ["/app/certs"]

USER node

# Unhealthy when the API stops answering, so restarts and orchestrators notice
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["node", "scripts/healthcheck.js"]

# node receives SIGTERM directly (exec form) and shuts down gracefully
CMD ["node", "server.js"]
