ARG JENKINS_IMAGE=jenkins/jenkins:2.441-jdk17@sha256:6bb8ea0eda544dddee8b3794936bd239e77281d59cce0f76586fa2c262e056f8
FROM ${JENKINS_IMAGE}
USER root
COPY fixtures.json /opt/module-target-fixtures.json
COPY init.groovy /usr/share/jenkins/ref/init.groovy.d/module-target.groovy
RUN install -d -o jenkins -g jenkins /opt/module-target \
    && printf 'module-target-root-only\n' > /opt/module-target-denied.txt \
    && chmod 600 /opt/module-target-denied.txt
USER jenkins
