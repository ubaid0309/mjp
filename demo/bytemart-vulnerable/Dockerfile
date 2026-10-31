# DEMO DATA - intentionally insecure container definition
FROM python:3.12-slim
WORKDIR /app
COPY shop/ .
RUN pip install flask requests pycryptodome pyjwt
USER root
CMD ["python", "app.py"]
