# ============================================================
# API 镜像（PROJECT_PLAN.md §2 `Dockerfile` / §5.10 P9 部署）
#   构建：docker compose build api      或   docker build -t aisec-intel-api .
#   运行：docker compose up -d api      （默认端口 8000）
#   - 依赖走清华镜像，加速国内构建（§环境约束）
#   - src 布局可编辑安装：aisec_intel 在容器内任意目录可 import
#   - 默认不装 sentence-transformers（避免 torch+CUDA 拖到 5GB+，容器内走哈希嵌入降级）；
#     需要真嵌入：docker build --build-arg WITH_EMBEDDING_MODEL=1 .
# ============================================================
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    PIP_TRUSTED_HOST=pypi.tuna.tsinghua.edu.cn \
    EMBEDDING_BACKEND=hashing

WORKDIR /app

# ① 先装依赖：requirements 不变时该层命中缓存
COPY requirements-docker.txt ./
RUN pip install --no-cache-dir -r requirements-docker.txt

# ② 可选：真实嵌入模型（体积约 +2GB，默认关闭）
ARG WITH_EMBEDDING_MODEL=0
RUN if [ "$WITH_EMBEDDING_MODEL" = "1" ]; then pip install --no-cache-dir "sentence-transformers>=3.0"; fi

# ③ 再拷代码并做可编辑安装（--no-deps：依赖已在上一层装好）
COPY pyproject.toml README.md alembic.ini ./
COPY src ./src
COPY configs ./configs
COPY scripts ./scripts
COPY migrations ./migrations
RUN pip install --no-cache-dir --no-deps -e .

# 运行时数据（原始快照 / Chroma 持久化）挂到数据卷，避免写进镜像层
ENV RAW_SNAPSHOT_DIR=/data/raw \
    CHROMA_PATH=/data/chroma
VOLUME ["/data"]

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=45s --retries=10 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "aisec_intel.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

