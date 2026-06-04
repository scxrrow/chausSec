FROM python:3.12-alpine

WORKDIR /app

COPY . /app

RUN --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/ && \
    uv pip install --system --break-system-packages .

EXPOSE 5010

CMD ["uv", "run", "main.py"]