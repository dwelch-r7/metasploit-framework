# syntax=docker/dockerfile:1
FROM maven:3.9.9-eclipse-temurin-8@sha256:e20e4fc05fb5480c884a1f750c362ed0e91aca15cec5736e12796713710ec9b3 AS build
ARG TEXT_VERSION=1.8
ARG ALLOW_POST=false
ADD --checksum=sha256:e215506b741661e98567f79a338a5ae0cd12dfc47284516c55d312c0bcb7b793 https://codeload.github.com/karthikuj/cve-2022-42889-text4shell-docker/tar.gz/288959eddad312218ec31c7bc06cf2622b26e91e /tmp/application.tar.gz
WORKDIR /build
RUN tar -xzf /tmp/application.tar.gz --strip-components=1 && \
    cp src/main/java/com/levo/dockerexample/controller/HelloController.java /tmp/original-controller.java && \
    test "$(grep -c '<version>1.8</version>' pom.xml)" = 1 && \
    sed -i "s/<version>1.8<\/version>/<version>${TEXT_VERSION}<\/version>/" pom.xml && \
    if [ "$ALLOW_POST" = true ]; then sed -i 's/method = RequestMethod.GET/method = { RequestMethod.GET, RequestMethod.POST }/' src/main/java/com/levo/dockerexample/controller/HelloController.java; else test "$ALLOW_POST" = false; fi
COPY NativeControl.java src/main/java/NativeControl.java
RUN MAVEN_OPTS=-Xmx256m mvn --batch-mode --no-transfer-progress -DskipTests package

FROM eclipse-temurin:8-jdk-jammy@sha256:c6bac7c75823864b6317e0ed70e5ac1ec15e65180b4c4ccf09ca2ebf8a8f5f99
COPY --from=build /build/target/text4shell-poc.jar /opt/text4shell.jar
COPY --from=build /tmp/original-controller.java /opt/vendor/original-controller.java
COPY --from=build /build/src/main/java/com/levo/dockerexample/controller/HelloController.java /opt/vendor/controller.java
COPY --from=build /build/pom.xml /opt/vendor/pom.xml
COPY NativeControl.java /opt/vendor/NativeControl.java
RUN command -v curl && command -v base64 && command -v stat && mkdir /opt/module-target-state && chown 1000:1000 /opt/module-target-state
USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["java", "-Xms32m", "-Xmx160m", "-Dfile.encoding=UTF-8", "-jar", "/opt/text4shell.jar"]
