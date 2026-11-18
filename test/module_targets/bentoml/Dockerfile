FROM python:3.12.12-slim-bookworm@sha256:2986c55feb36e6cae00fa1fefb454283e4b33f35e75ff8bdd123b134130be301
ARG BENTOML_VERSION
ENV BENTOML_DO_NOT_TRACK=True PYTHONUNBUFFERED=1 BENTOML_HOME=/home/lab/bentoml OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY requirements-*.txt /requirements/
RUN pip install --disable-pip-version-check --no-cache-dir --only-binary=:all: --require-hashes -r /requirements/requirements-${BENTOML_VERSION}.txt && pip check
RUN useradd --create-home --uid 1000 lab && mkdir -p /lab /home/lab/bentoml && chown -R lab:lab /lab /home/lab
WORKDIR /lab
COPY --chown=1000:1000 model.py seed.py service.py legacy_service.py bentofile.yaml /lab/
USER lab
RUN python3 seed.py
CMD ["bentoml", "serve", "service:Echo", "--production", "--host", "0.0.0.0", "--port", "3000"]
