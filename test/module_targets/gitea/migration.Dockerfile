FROM python:3.12.12-slim-bookworm@sha256:2986c55feb36e6cae00fa1fefb454283e4b33f35e75ff8bdd123b134130be301
COPY native_migration.py /opt/native_migration.py
USER 65534:65534
CMD ["python", "-u", "/opt/native_migration.py"]
