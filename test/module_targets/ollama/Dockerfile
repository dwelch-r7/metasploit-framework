FROM ollama/ollama@sha256:c9bfaf0363f600acf1f7953152dfd56100d6a22cfbddb2f406dea999591f3117
RUN apt-get update && apt-get install -y --no-install-recommends python3-minimal && rm -rf /var/lib/apt/lists/*
COPY download_model.py native_probe.py start.sh health.py /lab/
RUN python3 /lab/download_model.py
ENTRYPOINT ["bash", "/lab/start.sh"]
