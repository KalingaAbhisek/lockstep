FROM maven:3.9.11-eclipse-temurin-21 AS build

WORKDIR /workspace
COPY pom.xml ./
COPY server/pom.xml server/pom.xml
COPY server/src server/src
RUN mvn -B -pl server -am package -DskipTests
# An extracted application starts faster than running classes from inside the nested fat jar.
RUN java -Djarmode=tools -jar server/target/authsync-server-*.jar extract \
        --destination /workspace/application \
        --application-filename app.jar

FROM eclipse-temurin:25-jre

# The Ubuntu 26.04 base ships Pebble (/usr/bin/pebble), a service manager this image never runs; its Go
# runtime carries high-severity standard-library CVEs until Canonical rebuilds it. Removing it leaves
# nothing to exploit and keeps the image scan in CI meaningful.
RUN rm -f /usr/bin/pebble

# Take Ubuntu's published security fixes now instead of waiting for a new base image (the CI image scan
# fails on any HIGH/CRITICAL finding that already has a fix, for example in apt).
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /workspace/application /app/application

# The serial collector suits Cloud Run's single CPU. The heap may use 75% of the container's memory (the
# JVM default is 25%, about 128 MiB on a 512 MiB instance), which leaves room for a 1,000-account rotation.
# -XX:TieredStopAtLevel=1 (faster startup, slower steady state) was rejected earlier because the server
# then ran PBKDF2 passphrase checks; it no longer does, so it may be worth measuring again by setting
# JAVA_OPTS="-XX:+UseSerialGC -XX:MaxRAMPercentage=75 -XX:TieredStopAtLevel=1" on the service.
# Override JAVA_OPTS on the service if you want different settings.
ENV JAVA_OPTS="-XX:+UseSerialGC -XX:MaxRAMPercentage=75"

# Class-data-sharing (CDS) archive: start the application once during the build, record the classes it
# loads, and reuse that archive at runtime so the JVM starts noticeably faster. The training run exits
# as soon as the Spring context is ready and never connects to Firestore. If it fails for any reason the
# image still builds and simply starts without the archive.
RUN java $JAVA_OPTS -XX:ArchiveClassesAtExit=/app/application/app.jsa -Dspring.context.exit=onRefresh \
        -jar /app/application/app.jar \
    || (echo "CDS training run failed; continuing without the archive" && rm -f /app/application/app.jsa)

ENV PORT=8080
EXPOSE 8080
USER 65532:65532

ENTRYPOINT ["sh", "-c", "if [ -f /app/application/app.jsa ]; then CDS=-XX:SharedArchiveFile=/app/application/app.jsa; else CDS=; fi; exec java $CDS $JAVA_OPTS -jar /app/application/app.jar"]
