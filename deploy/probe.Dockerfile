# scanent-probe's container image: the active flavour (docs/design/active-flavour.md).
# Build it from the repository root:
#
#   docker build -f deploy/probe.Dockerfile -t scanent-probe .
#
# A SEPARATE IMAGE, never a mode of the read-only scanner's (decision 1): that
# image's Dockerfile and build context name nothing of the prober, and this one
# carries nothing of the scanner. It is built and tested in CI and NOT
# published: whether and where it is published is a decision the owner has not
# taken yet (2026-11-24).
#
# WHAT THE RUNTIME STAGE ADDS TO THE BASE IMAGE, AND NOTHING ELSE. The compiled
# JavaScript of packages/probe and of the contract it imports, their manifests,
# LICENSE and NOTICE, and zod, the one production dependency either has. No
# TypeScript source, no compiler, no test tooling, no package manager, and no
# file of the scanner. The bases are the read-only image's, by the same
# digests: the bytes CI scans are the bytes a client builds.
#
# The build context is limited by deploy/probe.Dockerfile.dockerignore, an
# allowlist of exactly what the build stage copies.
# packages/scanner/tests/image.test.ts holds the two to each other.

# ─── Stage 1: compile, then assemble the runtime tree in /out ───
FROM node:24-alpine@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8 AS build
WORKDIR /src

# The root lockfile names four workspaces, so `npm ci` needs each manifest. Only
# the contract's and the prober's sources are copied, and only they are built.
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/contract/package.json packages/contract/tsconfig.json ./packages/contract/
COPY packages/scanner/package.json ./packages/scanner/
COPY packages/report/package.json ./packages/report/
COPY packages/probe/package.json packages/probe/tsconfig.json ./packages/probe/
# `npm ci`: exactly the lockfile's tree, or a failure. No install script runs.
# The optional `ca` secret is as in deploy/Dockerfile: for a build behind a
# TLS-inspecting proxy, this step only, and nothing of it reaches a layer.
RUN --mount=type=secret,id=ca,required=false \
    NODE_EXTRA_CA_CERTS=/run/secrets/ca npm ci --ignore-scripts --no-audit --no-fund

COPY packages/contract/src ./packages/contract/src
COPY packages/probe/src ./packages/probe/src
# `tsc -b` builds the contract first: the prober's tsconfig references it.
RUN npx tsc -b packages/probe

COPY LICENSE NOTICE ./

# The runtime tree, by hand and by name: the prober, the contract where Node
# resolves `@rodnapamet/scanent-contract`, and zod. Then drop what nothing runs
# (declaration and map files), and check the tree resolves what the prober
# imports, from where it runs.
RUN mkdir -p /out/node_modules/@rodnapamet/scanent-contract /out/packages/probe \
    && cp -R node_modules/zod /out/node_modules/zod \
    && cp packages/contract/package.json /out/node_modules/@rodnapamet/scanent-contract/package.json \
    && cp -R packages/contract/dist /out/node_modules/@rodnapamet/scanent-contract/dist \
    && cp packages/probe/package.json /out/packages/probe/package.json \
    && cp -R packages/probe/dist /out/packages/probe/dist \
    && cp LICENSE NOTICE /out/ \
    && find /out/node_modules/@rodnapamet/scanent-contract/dist /out/packages/probe/dist -type f ! -name '*.js' -delete \
    && test -f /out/packages/probe/dist/cli.js \
    && (cd /out/packages/probe && node -e "for (const m of ['@rodnapamet/scanent-contract/harness-contract', '@rodnapamet/scanent-contract/probes-contract', 'zod', './dist/cli.js']) require(m)")

# ─── Stage 2: the runtime ───
# The read-only image's distroless base: the Node binary, its C library, the CA
# bundle and a time-zone database. No shell and no package manager.
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:39b0407357c9fadf1a9708d22088f02de21f0e1e8a688474eea2d8701e7d5693 AS runtime

ENV PATH=/nodejs/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

LABEL org.opencontainers.image.title="scanent-probe" \
      org.opencontainers.image.description="scanent-probe, the active flavour: probes an agent only under a signed engagement scope" \
      org.opencontainers.image.vendor="Inflect Ltd." \
      org.opencontainers.image.licenses="BUSL-1.1"

WORKDIR /app
ENV NODE_ENV=production
# As in the read-only image: with no proxy variable set this changes nothing.
ENV NODE_USE_ENV_PROXY=1

COPY --from=build /out /app

# Uid and gid 1000, by number: never root. Nothing under /app is writable by
# it; the report is written to a mounted directory.
USER 1000:1000

# Exec form, one process. With no arguments it prints its help.
ENTRYPOINT ["node", "/app/packages/probe/dist/cli.js"]
