# syntax=docker/dockerfile:1.7
#
# nfs-ganesha commit image: the org C/C++ base + the pinned libntirpc source cache + mayhem/build.sh.
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

# libntirpc is a git submodule (src/libntirpc, gitlink c9db96b2c361) that a plain checkout does not
# materialize. Cache the pinned commit's source for the offline build (SPEC section 6.2 item 19);
# build.sh builds it out of tree with the fuzz flags.
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends \
        liburcu-dev libcap-dev uuid-dev libacl1-dev libblkid-dev \
 && rm -rf /var/lib/apt/lists/*
ARG NTIRPC_VER=c9db96b2c361
ARG NTIRPC_COMMIT=c9db96b2c361dba034bdb286743f04a4c8fbb61e
ARG NTIRPC_SHA256=9f40b34bb91a13cb7f42a053178d728d4ab5c9623ffd33813ad4641948385551
RUN d=/opt/toolchains/deps/ntirpc-${NTIRPC_VER} && mkdir -p "$d/src" \
 && curl -fsSL -o /tmp/ntirpc.tgz https://github.com/nfs-ganesha/ntirpc/archive/${NTIRPC_COMMIT}.tar.gz \
 && echo "${NTIRPC_SHA256}  /tmp/ntirpc.tgz" | sha256sum -c - \
 && tar -xzf /tmp/ntirpc.tgz --strip-components=1 -C "$d/src" \
 && rm -f /tmp/ntirpc.tgz && chmod -R a+rX "$d"

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

RUN bash mayhem/test.sh

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
