# Deliberately misconfigured fixture for the IaC capability demo.
FROM python:latest
USER root
COPY . /app
RUN pip install -r /app/requirements.txt
CMD ["python", "/app/app.py"]
