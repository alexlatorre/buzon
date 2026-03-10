FROM node:20-alpine

WORKDIR /app

# Install build dependencies for better-sqlite3 (native module)
RUN apk add --no-cache python3 make g++

# Copy package files and install dependencies
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy application source
COPY server.js config.js db.js ./
COPY db/ ./db/
COPY public/ ./public/

# Create data directory for volume mount
RUN mkdir -p /app/data /app/certs

# Expose HTTPS port
EXPOSE 4000

# Data volume — mount here for persistent storage (DB + uploaded files)
VOLUME ["/app/data"]

# SSL certs — mount your Let's Encrypt certs here:
#   -v /path/to/fullchain.pem:/app/certs/fullchain.pem
#   -v /path/to/privkey.pem:/app/certs/privkey.pem
# If no certs are mounted, the server starts in HTTP mode.
VOLUME ["/app/certs"]

CMD ["node", "server.js"]
