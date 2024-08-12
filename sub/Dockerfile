FROM python:3.12-slim
WORKDIR /code

COPY . .
RUN pip install --no-cache-dir --upgrade -r requirements.txt


CMD ["gunicorn", "-w", "4", "sub:app", "-b", "0.0.0.0:80"]