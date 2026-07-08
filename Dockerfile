FROM node:24-slim AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
ENV CI=true
ENV ARGOCD_BASE_URL="https://argocdgenai-dh-sb.awgp.xyz"
ENV MCP_URL="https://argocd-mcp-103611092023.us-east4.run.app"
RUN corepack enable
COPY . /app
WORKDIR /app

FROM base AS prod-deps
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --prod --frozen-lockfile

FROM base AS build
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile --unsafe-perm
RUN pnpm run build


FROM base
COPY --from=prod-deps /app/node_modules /app/node_modules
COPY --from=build /app/dist /app/dist
EXPOSE 8080
CMD [ "sh", "-c", "node dist/index.js http --port 8080 --server-url ${ARGOCD_BASE_URL} --callback-port ${CALLBACK_PORT:-443} --mcp-url ${MCP_URL}" ]
