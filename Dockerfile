# voyager-agent — the one universal Voyager, containerized.
#   docker run --rm ghcr.io/dir-ai/voyager-agent mission "audit my repo" --repo /work
#   (mount a repo at /work with -v "$PWD:/work:ro")
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --no-audit --no-fund
COPY src ./src
RUN npm run build
FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY server.json LICENSE README.md ./
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["help"]
