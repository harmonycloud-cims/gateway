FROM openshift/java:8
WORKDIR /usr/src/app
COPY target/*.jar ./app.jar
ENTRYPOINT ["java","-jar","./app.jar", "--port=80"]