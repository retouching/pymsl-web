# syntax=docker/dockerfile:1
# The fake MSL server of the e2e stack (docker/compose.e2e.yaml): Python, cryptography and the code of
# tests/e2e/server alone, which never imports pymsl_web.
FROM python:3.14-slim
RUN pip install --no-cache-dir cryptography==50.0.2 \
    && useradd --create-home --uid 10001 msl
COPY tests/__init__.py /opt/msl/tests/__init__.py
COPY tests/e2e/__init__.py /opt/msl/tests/e2e/__init__.py
COPY tests/e2e/server /opt/msl/tests/e2e/server
WORKDIR /opt/msl
USER msl
EXPOSE 8080
CMD ["python", "-m", "tests.e2e.server"]
