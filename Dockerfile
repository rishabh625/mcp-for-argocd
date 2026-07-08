FROM node:24-slim AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
# Run pnpm non-interactively: without a TTY, pnpm 10 otherwise aborts when it
# needs to purge node_modules (ERR_PNPM_ABORTED_REMOVE_MODULES_DIR_NO_TTY).
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
