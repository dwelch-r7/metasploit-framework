FROM apache/nifi:1.21.0@sha256:515559ab6fc2bb650eeb74bef5d8109073b2a4e8c64a7bf56825bcbf6fa3d315

# The existing native session launcher needs Python. Application startup still
# runs the original vendor script as the original nifi user.
USER root
RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3=3.10.6-1~22.04.1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1001 --create-home --shell /bin/bash labuser
COPY linux_post/launch_session.py /opt/launch_session.py
COPY nifi_credentials/launch_nifi_session.py /opt/launch_nifi_session.py
USER nifi
