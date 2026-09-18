FROM python:3.12-slim

RUN groupadd --system certwatcher && \
    useradd --system --gid certwatcher --create-home certwatcher

WORKDIR /app

COPY scripts/cert-requirements.txt .

RUN pip install --no-cache-dir -r cert-requirements.txt

COPY scripts/certwatcher.py .

RUN chown -R certwatcher:certwatcher /app

USER certwatcher

CMD ["python", "certwatcher.py"]
