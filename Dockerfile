# icloud-mcp + icloud-auth（一个镜像，Pod 里两个容器用不同 command）
#
# 上游：tomernation/icloud-mcp（MIT）固定 commit，构建时打 patches/ 下的补丁（不 fork）：
#   0001 Go 出站走 HTTPS_PROXY（出口只有 HTTP CONNECT 代理的环境）
#   0002 MCP_PLAIN_HTTP 模式：明文 HTTP + Host 白名单 + 可选静态 Bearer（Open WebUI 连得上）
#   0003 中国大陆区：白名单加 *.icloud.com.cn，ICLOUD_CALDAV_BASE_URL 选入口（只允许两个 Apple 值）
# pyicloud：按上游 scripts/reminders-probe-requirements.txt（pyicloud[cli]@86c4bc90，不能去掉 [cli]）
# 构建：.github/workflows/icloud-mcp-image.yml（GitHub Actions，linux/amd64 → ghcr.io/mouse9527/icloud-mcp）
# 改基础镜像来源（如私有镜像代理）：--build-arg BASE=<registry>/library
ARG BASE=docker.io/library

FROM ${BASE}/golang:1.26 AS build
ARG UPSTREAM_COMMIT=c027fd74c3f1e8435313830b70adcc63bad898ca
WORKDIR /src
RUN git clone https://github.com/tomernation/icloud-mcp.git . && git checkout --detach ${UPSTREAM_COMMIT}
COPY patches/ /patches/
RUN git apply /patches/*.patch && go vet ./... && go test ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /icloud-mcp ./cmd/icloud-mcp

FROM ${BASE}/python:3.13-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/scripts/reminders-probe-requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/reminders && /opt/reminders/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
 && apt-get purge -y git && apt-get autoremove -y && rm /tmp/requirements.txt
COPY --from=build /src/scripts/reminders_worker.py /opt/icloud/reminders_worker.py
COPY reminders_worker_reload.py icloud_auth.py /opt/icloud/
COPY --from=build /icloud-mcp /icloud-mcp
RUN useradd --uid 65532 --no-create-home --home-dir /tmp nonroot
USER 65532:65532
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/icloud
LABEL org.opencontainers.image.source="https://github.com/mouse9527/icloud-mcp" \
      org.opencontainers.image.description="tomernation/icloud-mcp c027fd7 + home patches + icloud-auth"
ENTRYPOINT ["/icloud-mcp"]
CMD ["-http", ":8080"]
