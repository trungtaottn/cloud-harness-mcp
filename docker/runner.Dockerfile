FROM node:24.11.0-alpine3.22 AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY apps/api/package.json apps/api/tsconfig.json ./apps/api/
COPY apps/runner/package.json apps/runner/tsconfig.json ./apps/runner/
COPY packages/contracts/package.json packages/contracts/tsconfig.json ./packages/contracts/
RUN npm ci
COPY apps/runner/src ./apps/runner/src
COPY packages/contracts/src ./packages/contracts/src
RUN npm run build -w @cloud-harness/contracts && npm run build -w @cloud-harness/runner && npm prune --omit=dev

FROM node:24.11.0-alpine3.22
LABEL io.cloud-harness.vm-workspaces="1"
LABEL io.cloud-harness.instabox-workspaces="1"
RUN apk add --no-cache docker-cli tini
ENV NODE_ENV=production
WORKDIR /app
RUN mkdir -p /app/apps/runner /app/packages/contracts \
  && chmod 0755 /app/apps /app/apps/runner /app/packages /app/packages/contracts
COPY --from=build --chmod=0444 /app/package.json /app/package-lock.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build --chmod=0444 /app/apps/runner/package.json ./apps/runner/package.json
COPY --from=build /app/apps/runner/dist ./apps/runner/dist
COPY --from=build --chmod=0444 /app/packages/contracts/package.json ./packages/contracts/package.json
COPY --from=build /app/packages/contracts/dist ./packages/contracts/dist
COPY --chmod=0444 worker/remote-executor.mjs worker/harness-worker.mjs worker/workspace-transfer.mjs worker/git-transfer-helper.sh ./worker/
RUN chmod 0755 /app/worker
EXPOSE 3001
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "apps/runner/dist/index.js"]
