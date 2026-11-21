ARG OLLAMA_IMAGE=ollama/ollama@sha256:4b11fdc55cec0a227f3f3ba9b8910940f892f98252141c97ed3bc4b45507d08d
FROM ${OLLAMA_IMAGE} AS native_builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY native_loader.c /native_loader.c
RUN gcc -Wall -Wextra -Werror -shared -fPIC -O2 -o /native-loader.so /native_loader.c \
    && gcc --version > /native-compiler.txt

FROM ${OLLAMA_IMAGE}
# Installing the observer must retain both vendor code and the original loader.
RUN sha256sum /bin/ollama /lib/x86_64-linux-gnu/libc.so.6 /lib64/ld-linux-x86-64.so.2 > /vendor.sha256 \
    && apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/* && sha256sum -c /vendor.sha256
COPY --from=native_builder /native-loader.so /opt/module-target/native-loader.so
COPY --from=native_builder /native-compiler.txt /opt/module-target/native-compiler.txt
COPY observer.py /opt/module-target/observer.py
ENTRYPOINT ["python3", "/opt/module-target/observer.py"]
