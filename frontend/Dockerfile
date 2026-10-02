# ============================================================
# Streamlit 前端镜像（PROJECT_PLAN.md §5.9 P8 / §5.10 P9）
#   构建：docker compose build frontend
#   运行：docker compose up -d frontend      （默认端口 8501）
#   - 前端只消费 API（§2.1：frontend/ 不 import aisec_intel、不直连库）
#   - 依赖仅 4 个（streamlit / requests / pyvis / pandas），镜像体积远小于 API
# ============================================================
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    PIP_TRUSTED_HOST=pypi.tuna.tsinghua.edu.cn \
    API_BASE_URL=http://api:8000/api/v1

WORKDIR /app

COPY frontend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 前端代码 + 数据质量报告（页面④直接渲染 reports/*.md）
COPY frontend ./frontend
COPY reports ./reports

WORKDIR /app/frontend

EXPOSE 8501

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=10 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4).status == 200 else 1)"

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
