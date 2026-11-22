FROM couchdb:3.2.1@sha256:37a7a9aab050c8c376b012d9c52da58e2c94d221b0eb5567edb88d8ceca096ee

# The unchanged owning Linux target uses wget. Install that genuine target
# prerequisite; CouchDB and its bundled OTP binaries remain unmodified.
USER root
# A dated signed Debian index avoids disappearing historical package URLs.
RUN printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20220501T000000Z/ bullseye main' > /etc/apt/sources.list \
 && apt-get update \
 && apt-get install --yes --no-install-recommends wget=1.21-1+deb11u1 \
 && rm -rf /var/lib/apt/lists/*
