FROM java:8-jdk-alpine
WORKDIR /usr/src/app
COPY target/*.jar ./app.jar
ENTRYPOINT ["java","-jar","./app.jar", "--port=80"]