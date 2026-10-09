# Multi-stage build. The gateway needs JDK 24 (see pom.xml).
ARG JDK=24

FROM maven:3.9-eclipse-temurin-${JDK} AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -B -ntp -q -DskipTests package && cp target/*.jar /app.jar

FROM eclipse-temurin:${JDK}-jre
RUN useradd --system --uid 10001 --create-home app
COPY --from=build /app.jar /app.jar
USER app
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=40s --retries=5 \
  CMD curl -fsS http://localhost:8080/actuator/health/readiness || exit 1
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=60", "-jar", "/app.jar"]
