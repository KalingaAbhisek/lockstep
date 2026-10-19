FROM maven:3.9.11-eclipse-temurin-21 AS build

WORKDIR /workspace
COPY pom.xml ./
COPY server/pom.xml server/pom.xml
COPY server/src server/src
RUN mvn -B -pl server -am package -DskipTests

FROM eclipse-temurin:21-jre

WORKDIR /app
COPY --from=build /workspace/server/target/authsync-server-*.jar app.jar

ENV PORT=8080
EXPOSE 8080
USER 65532:65532

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
