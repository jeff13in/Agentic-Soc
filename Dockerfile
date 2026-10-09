# API image: FastAPI + agent + evals. The dataset is built on first start (see docker/entrypoint.sh).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY agent agent
COPY api api
COPY data data
COPY evals evals
COPY training/__init__.py training/build_sft_data.py training/
COPY tests/fixtures tests/fixtures
RUN pip install .

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Generated data, the trace store and eval results live on volumes.
VOLUME ["/app/data/generated", "/app/data/labels", "/app/var", "/app/evals/results"]
EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
