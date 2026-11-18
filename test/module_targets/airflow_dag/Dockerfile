ARG AIRFLOW_IMAGE=apache/airflow:1.10.10@sha256:b67062e5c67906391f7023b1c0ec7b51f8d4d4be1230e96c1e375d98e696f02a
FROM ${AIRFLOW_IMAGE}
# The historical image lacks the vendor-documented password extra. Install only
# its checksum-pinned wrapper, offline, using the image's existing bcrypt/Flask.
COPY --from=password_package /Flask-Bcrypt-0.7.1.tar.gz /tmp/Flask-Bcrypt-0.7.1.tar.gz
RUN echo 'd71c8585b2ee1c62024392ebdbc447438564e2c8c02b4e57b56a4cafd8d13c5f  /tmp/Flask-Bcrypt-0.7.1.tar.gz' | sha256sum -c - \
 && python -m pip install --no-cache-dir --user --no-index --no-deps /tmp/Flask-Bcrypt-0.7.1.tar.gz \
 && python -c 'import airflow,flask_bcrypt,bcrypt;print(airflow.__version__)'
COPY profiles.json deploy.py seed.py start.sh fixed-example.py control.py /opt/module-target/
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["bash", "/opt/module-target/start.sh"]
