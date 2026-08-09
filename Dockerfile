# kiwi-catalog standalone service (阶段 4 部署)
# 单容器形态：SQLite 文件放持久卷，SSRF fetcher 的 socket 级防护原样工作。

FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0

# Run the service as an unprivileged user.
RUN groupadd --gid 10001 kiwi && \
    useradd --uid 10001 --gid kiwi --shell /usr/sbin/nologin --create-home kiwi

WORKDIR /app

COPY pyproject.toml ./
COPY uv.lock ./
COPY README.md LICENSE ./
COPY kiwi_catalog ./kiwi_catalog

RUN python -m pip install --no-cache-dir "uv==0.10.6" \
    && uv export --locked --no-dev --extra api --no-emit-project --format requirements.txt > /tmp/requirements.txt \
    && python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && python -m pip install --no-cache-dir --no-deps . \
    && rm -f /tmp/requirements.txt

# Keep the SQLite volume writable after dropping privileges.
RUN mkdir -p /data && chown kiwi:kiwi /data

# 敏感配置不落镜像层——运行时经 docker run -e 注入：
#   -e KIWI_CATALOG_ADMIN_TOKEN=<admin> -e KIWI_CATALOG_OWNER_TOKEN_SECRET=<secret>
# db 路径固定 /data/catalog.sqlite（VOLUME /data）。

VOLUME ["/data"]
EXPOSE 8600

USER kiwi

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8600/health', timeout=3)"]

CMD ["python", "-m", "kiwi_catalog.scripts.kiwi_catalog_api", "--db", "/data/catalog.sqlite", "--host", "0.0.0.0", "--port", "8600"]
