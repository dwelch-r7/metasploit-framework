ARG UNIFI_IMAGE=jacobalberty/unifi@sha256:dde2fb3f836325887e0de9254a9e4ca6230f48ebc58b0db433f7d6bceeebfc9f
FROM ${UNIFI_IMAGE} AS vendor
FROM eclipse-temurin:8-jdk-jammy@sha256:c6bac7c75823864b6317e0ed70e5ac1ec15e65180b4c4ccf09ca2ebf8a8f5f99 AS compiler
WORKDIR /proof
COPY --from=vendor /usr/lib/unifi/lib/tomcat-embed-core-*.jar /vendor/
COPY IdentityAgent.java NativeBeanFactory.java ./
RUN javac -cp '/vendor/*' IdentityAgent.java NativeBeanFactory.java && \
    printf 'Premain-Class: IdentityAgent\n\n' > agent-manifest.mf && \
    jar cfm identity-agent.jar agent-manifest.mf IdentityAgent*.class
FROM vendor
COPY --from=compiler /proof/identity-agent.jar /proof/NativeBeanFactory.class /opt/module-target/
COPY configure-lab.sh /usr/local/unifi/init.d/10-module-target-limits
RUN chmod +x /usr/local/unifi/init.d/10-module-target-limits
