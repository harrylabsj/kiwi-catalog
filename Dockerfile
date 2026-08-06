# kiwi-catalog standalone service (阶段 4 部署)
# 单容器形态：SQLite 文件放持久卷，SSRF fetcher 的 socket 级防护原样工作。

FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml ./
COPY kiwi_catalog ./kiwi_catalog

RUN pip install --no-cache-dir .[api]

ENV KIWI_CATALOG_ADMIN_TOKEN="" \
    KIWI_CATALOG_OWNER_TOKEN_SECRET="" \
    KIWI_CATALOG_DB=/data/catalog.sqlite

VOLUME ["/data"]
EXPOSE 8600

CMD ["python", "-m", "kiwi_catalog.scripts.kiwi_catalog_api", "--db", "/data/catalog.sqlite", "--host", "0.0.0.0", "--port", "8600"]
