# scanent's container image. Build it from the repository root:
#
#   docker build -f deploy/Dockerfile -t scanent .
#
# Running it is in README.md, "Quick start, container".
#
# WHAT THE RUNTIME STAGE HOLDS, AND NOTHING ELSE. The compiled JavaScript of
# the two packages that run (packages/contract and packages/scanner, each
# `dist/`), their manifests, and the production dependencies the lockfile
# gives them: zod, js-yaml (with argparse) and typescript. `typescript` is a
# run-time dependency on purpose: the `code` source reads an estate's
# JavaScript and TypeScript with its parser. There is no TypeScript source, no
# compiler step at start, no test tooling and no package manager.
#
# The build context is limited to what the COPY lines below name by the
# allowlist in `.dockerignore`. packages/scanner/tests/image.test.ts holds the
# two to each other.
#
# The base image is pinned by digest. This image runs in a client's estate and
# holds the key its reports are signed with, so the bytes a client builds are
# the bytes CI scanned. Dependabot proposes the digest's updates.

# ─── Stage 1: compile, then cut node_modules down to production ───
FROM node:24-alpine@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8 AS build
WORKDIR /src

COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/contract/package.json packages/contract/tsconfig.json ./packages/contract/
COPY packages/scanner/package.json packages/scanner/tsconfig.json ./packages/scanner/
COPY packages/report/package.json ./packages/report/
# `npm ci`: exactly the lockfile's tree, or a failure. No install script runs.
RUN npm ci --ignore-scripts --no-audit --no-fund

COPY packages/contract/src ./packages/contract/src
COPY packages/scanner/src ./packages/scanner/src
RUN npm run build

# The production tree, from the same lockfile. Then drop what nothing runs:
# the workspace link to the report package (no code yet), the `.bin` links
# (the entrypoint names its file), and the declaration and map files tsc
# writes beside the JavaScript.
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && rm -rf node_modules/@scanent/report node_modules/.bin packages/scanner/node_modules/.bin node_modules/.package-lock.json \
    && find packages/contract/dist packages/scanner/dist -type f ! -name '*.js' -delete \
    && test -f packages/scanner/dist/cli.js \
    && test -f node_modules/@scanent/contract/dist/harness-contract.js

# ─── Stage 2: the runtime ───
FROM node:24-alpine@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8 AS runtime

# No package manager at run time: the scanner installs nothing, and npm's own
# bundled dependencies are the base image's largest source of Trivy findings.
RUN rm -rf /usr/local/lib/node_modules/npm \
           /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm \
           /usr/local/bin/npx \
           /usr/local/bin/corepack \
           /opt/yarn-* \
           /usr/local/bin/yarn \
           /usr/local/bin/yarnpkg \
           /root/.npm \
    && ! command -v npm \
    && ! command -v npx \
    && ! command -v corepack \
    && ! command -v yarn

WORKDIR /app
ENV NODE_ENV=production

COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/packages/contract/package.json ./packages/contract/package.json
COPY --from=build /src/packages/contract/dist ./packages/contract/dist
COPY --from=build /src/packages/scanner/package.json ./packages/scanner/package.json
COPY --from=build /src/packages/scanner/dist ./packages/scanner/dist
COPY --from=build /src/packages/scanner/node_modules ./packages/scanner/node_modules

# The image's `node` user (uid 1000), never root. Nothing under /app is
# writable by it, and the scanner writes no file: it runs with a read-only
# root filesystem.
USER node

# Exec form, one process: `node` is PID 1, so the signal `docker stop` sends
# reaches the scanner itself. No shell is involved in starting it.
ENTRYPOINT ["node", "/app/packages/scanner/dist/cli.js"]
CMD ["schedule", "--config", "/etc/scanent/config.json"]
