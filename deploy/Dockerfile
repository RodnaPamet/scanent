# scanent's container image. Build it from the repository root:
#
#   docker build -f deploy/Dockerfile -t scanent .
#
# Running it is in README.md, "Quick start, container".
#
# WHAT THE RUNTIME STAGE ADDS TO THE BASE IMAGE, AND NOTHING ELSE. The
# compiled JavaScript of the three packages that run (packages/contract,
# packages/report and packages/scanner, each `dist/`), their manifests, LICENSE and NOTICE, and the
# production dependencies the lockfile gives them, as published: zod, js-yaml
# (with argparse) and typescript. `typescript` is a run-time dependency on
# purpose: the `code` source reads an estate's JavaScript and TypeScript with
# its parser. There is no TypeScript source of scanent's, no compiler step at
# start, no test tooling and no package manager. The base image's own files
# stay, less the package managers and its entrypoint script.
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
COPY packages/report/package.json packages/report/tsconfig.json ./packages/report/
# `npm ci`: exactly the lockfile's tree, or a failure. No install script runs.
#
# The optional `ca` build secret is for a build behind a TLS-inspecting proxy:
# `docker build --secret id=ca,src=/path/to/ca.pem ...` makes npm trust that
# certificate authority for this step only. Without the secret the mount is
# empty and the step is a plain `npm ci`. The lockfile's integrity hashes
# decide what is installed either way, and nothing of the secret reaches a
# layer.
RUN --mount=type=secret,id=ca,required=false \
    NODE_EXTRA_CA_CERTS=/run/secrets/ca npm ci --ignore-scripts --no-audit --no-fund

COPY packages/contract/src ./packages/contract/src
COPY packages/report/src ./packages/report/src
COPY packages/scanner/src ./packages/scanner/src
RUN npm run build

# The licence travels with every copy of the work.
COPY LICENSE NOTICE ./

# The production tree, from the same lockfile. Then drop what nothing runs:
# the `.bin` links (the entrypoint names its file), and the declaration and
# map files tsc writes beside the JavaScript.
#
# Where npm puts a dependency (the root node_modules, or one nested under a
# package) follows from the whole lockfile, development dependencies included,
# so it can move in a pull request that touched no run-time dependency. Every
# package's nested directory is therefore made to exist, and the runtime
# stage copies each whatever it holds. The last line is the check that the
# tree the runtime stage is about to copy resolves every declared dependency
# from where the code runs.
RUN --mount=type=secret,id=ca,required=false \
    NODE_EXTRA_CA_CERTS=/run/secrets/ca npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && mkdir -p packages/contract/node_modules packages/report/node_modules packages/scanner/node_modules \
    && rm -rf node_modules/.bin packages/contract/node_modules/.bin packages/report/node_modules/.bin packages/scanner/node_modules/.bin node_modules/.package-lock.json \
    && find packages/contract/dist packages/report/dist packages/scanner/dist -type f ! -name '*.js' -delete \
    && test -f packages/scanner/dist/cli.js \
    && test -f node_modules/@scanent/contract/dist/harness-contract.js \
    && test -f node_modules/@scanent/report/dist/results/score.js \
    && (cd packages/scanner && node -e "for (const m of ['@scanent/contract/harness-contract', 'js-yaml', 'typescript', 'zod']) require(m)") \
    && (cd packages/scanner && node -e "require('@scanent/report/results/score')") \
    && (cd packages/report && node -e "for (const m of ['@scanent/contract/harness-ladder', 'zod']) require(m)") \
    && (cd packages/contract && node -e "require('zod')")

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
           /usr/local/bin/docker-entrypoint.sh \
    && ! command -v npm \
    && ! command -v npx \
    && ! command -v corepack \
    && ! command -v yarn

LABEL org.opencontainers.image.title="scanent" \
      org.opencontainers.image.description="scanent, the Agent Estate Scanner" \
      org.opencontainers.image.vendor="Inflect Ltd." \
      org.opencontainers.image.licenses="BUSL-1.1"

WORKDIR /app
ENV NODE_ENV=production

COPY --from=build /src/LICENSE ./LICENSE
COPY --from=build /src/NOTICE ./NOTICE

COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/packages/contract/package.json ./packages/contract/package.json
COPY --from=build /src/packages/contract/dist ./packages/contract/dist
COPY --from=build /src/packages/contract/node_modules ./packages/contract/node_modules
COPY --from=build /src/packages/report/package.json ./packages/report/package.json
COPY --from=build /src/packages/report/dist ./packages/report/dist
COPY --from=build /src/packages/report/node_modules ./packages/report/node_modules
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
