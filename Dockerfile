# syntax=docker/dockerfile:1.7

# Multi-stage build. The gateway needs JDK 24 (see pom.xml).
ARG JDK=24

FROM maven:3.9-eclipse-temurin-${JDK} AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
# parkview-platform comes from GitHub Packages: the settings.xml (server id github) is a BuildKit secret, never part of a layer.
# docker build --secret id=maven_settings,src=$HOME/.m2/settings.xml
RUN --mount=type=secret,id=maven_settings,target=/root/.m2/settings.xml \
    --mount=type=cache,target=/root/.m2/repository \
    mvn -B -ntp -q -DskipTests package && cp target/*.jar /app.jar

FROM eclipse-temurin:${JDK}-jre
RUN useradd --system --uid 10001 --create-home app
COPY --from=build /app.jar /app.jar
USER app
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=40s --retries=5 \
  CMD wget -q -O /dev/null http://localhost:8080/actuator/health/readiness || exit 1
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=60", "-jar", "/app.jar"]
