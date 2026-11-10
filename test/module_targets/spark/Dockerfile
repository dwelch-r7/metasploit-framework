FROM eclipse-temurin:8-jdk-jammy@sha256:c6bac7c75823864b6317e0ed70e5ac1ec15e65180b4c4ccf09ca2ebf8a8f5f99
RUN apt-get update \
 && apt-get install --yes --no-install-recommends curl procps python3 python-is-python3 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1500 --user-group --no-create-home --home-dir /opt/spark --shell /bin/bash spark
ARG ARCHIVE_URL
ARG ARCHIVE_SHA512
ADD ${ARCHIVE_URL} /tmp/spark.tgz
RUN printf '%s  /tmp/spark.tgz\n' "$ARCHIVE_SHA512" | sha512sum --check - \
 && mkdir /opt/spark \
 && tar -xzf /tmp/spark.tgz --strip-components=1 -C /opt/spark \
 && rm /tmp/spark.tgz \
 && mkdir /opt/spark/work /opt/spark/logs /opt/spark/events \
 && chown -R spark:spark /opt/spark
COPY NativeProof.java /opt/module-target/
RUN javac -d /opt/module-target /opt/module-target/NativeProof.java \
 && jar cf /opt/module-target/native-proof.jar -C /opt/module-target NativeProof.class
ENV SPARK_HOME=/opt/spark SPARK_LOCAL_IP=0.0.0.0
WORKDIR /opt/spark
USER spark
