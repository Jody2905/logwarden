# Build
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src src
RUN mvn -q -B -DskipTests package && cp target/logwarden-*.jar /app.jar

# Run
FROM eclipse-temurin:17-jre
RUN useradd --system --uid 10001 logwarden
USER logwarden
COPY --from=build /app.jar /app/logwarden.jar
# Small-instance friendly: free hosting gives 512 MB
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70 -XX:+UseSerialGC -Xss512k -XX:TieredStopAtLevel=1"
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/logwarden.jar"]
