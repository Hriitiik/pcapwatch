FROM python:3.14-slim

RUN useradd -m app
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pcapwatch/ pcapwatch/
COPY examples/ examples/

USER app
ENTRYPOINT ["python", "-m", "pcapwatch"]