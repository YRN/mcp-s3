# syntax=docker/dockerfile:1
#
# mcp-s3 in HTTP mode (Streamable HTTP + OAuth), meant to run behind an HTTPS reverse proxy.
# See deploy/ for a Caddy example. Build: docker build -t mcp-s3 .
#
# The HTTP mode is always read-only. Required at runtime (see PLAN.md section 4):
#   S3_BUCKET, S3_ROOT_PREFIX, AWS_REGION, MCP_S3_TOKEN_KEY, MCP_S3_PUBLIC_URL,
#   MCP_S3_AUTH_USERNAME, MCP_S3_AUTH_PASSWORD, plus AWS credentials (read-only IAM user/role).

ARG NODE_IMAGE=node:24-alpine

# --- build: compile TypeScript --------------------------------------------------
FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json ./
# --ignore-scripts: no dependency needs an install script to compile (tsc is plain JS).
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# --- deps: production dependencies only -------------------------------------------
FROM ${NODE_IMAGE} AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force

# --- runtime --------------------------------------------------------------------
FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production \
    MCP_S3_TRANSPORT=http \
    MCP_S3_HTTP_HOST=0.0.0.0 \
    MCP_S3_HTTP_PORT=3000
WORKDIR /app
# Files stay owned by root and read-only for the runtime user.
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
# The official image ships an unprivileged "node" user (uid 1000).
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.MCP_S3_HTTP_PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "dist/index.js"]
