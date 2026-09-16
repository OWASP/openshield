FROM python:3.11-slim-trixie

WORKDIR /app

RUN apt-get update \
    && apt-get dist-upgrade -y \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade \
        pip==26.1.2 \
        setuptools==83.0.0 \
        wheel==0.46.3 && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python -m ai.embed

RUN groupadd --system openshield && \
    useradd --system --gid openshield --no-create-home openshield && \
    chown -R openshield:openshield /app

USER openshield

ENV PORT=8000

EXPOSE 8000

CMD ["./startup.sh"]
