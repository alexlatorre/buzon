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

# Copy SSL certificates (can be overridden with volume mount)
COPY cert.pem key.pem ./

# Create data directory for volume mount
RUN mkdir -p /app/data

# Expose HTTPS port
EXPOSE 4000

# Data volume — mount here for persistent storage (DB + uploaded files)
VOLUME ["/app/data"]

CMD ["node", "server.js"]
