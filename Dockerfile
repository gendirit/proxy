FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py detectors.py store.py writer.py config.json .

EXPOSE 8000

# Запуск через python main.py: автоопределение числа воркеров по CPU
# (WORKERS env переопределяет при необходимости)
CMD ["python", "main.py"]
