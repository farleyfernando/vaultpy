FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY main.py ./

RUN pip install --upgrade pip && pip install .

EXPOSE 8000

CMD ["python", "main.py"]
