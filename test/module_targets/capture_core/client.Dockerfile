FROM postgres:16@sha256:933463a6c8eba2b9f5cd414138738cd8d5519cd2c471214c222652f547a66a32
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends python3=3.13.5-1 python3.13=3.13.5-2+deb13u5 tcpdump=4.99.5-2 libpq5=18.6-1.pgdg13+2 \
    && dpkg-query -W python3 tcpdump postgresql-client-16 libpq5 > /opt/module-target-client-packages.txt \
    && rm -rf /var/lib/apt/lists/*
COPY client.py /opt/module-target-client.py
ENTRYPOINT []
CMD ["sleep", "infinity"]
