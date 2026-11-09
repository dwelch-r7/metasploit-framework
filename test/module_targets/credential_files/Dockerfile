FROM docker:27.5.1-cli@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c AS docker_client
FROM ruby:3.3.13-bookworm@sha256:ae098d019fd2995e6cb82e16a87529348ba26a7c83ad6189937decc2846b0730

RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends python3 openssh-server openssh-client apache2-utils libsqlite3-dev libyaml-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /opt/health /opt/credential-state \
    && printf 'Native credential file target\n' > /opt/health/index.html
COPY --from=docker_client /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /opt/gemstash
COPY credential_files/Gemfile credential_files/Gemfile.lock ./
RUN mkdir -p vendor/cache \
    && curl --fail --location --silent --show-error https://rubygems.org/downloads/gemstash-2.8.2.gem -o vendor/cache/gemstash-2.8.2.gem \
    && printf '%s  vendor/cache/gemstash-2.8.2.gem\n' 162250957aadbc5cdaf46a59b0d24a8a03360fe1cc4f12d6e2d6bbe4a5cceafe | sha256sum -c - \
    && bundle config set --local path /opt/gemstash/bundle \
    && bundle install --jobs 2 --retry 1
COPY linux_post/launch_session.py /opt/launch_session.py
COPY credential_files/seed.py credential_files/start.sh credential_files/gemstash.yml credential_files/native_probe.py credential_files/replay.py /opt/credential-fixture/
RUN chmod 755 /opt/credential-fixture/start.sh
WORKDIR /tmp
ENTRYPOINT ["/opt/credential-fixture/start.sh"]
