FROM java:8-jdk-alpine
WORKDIR /usr/src/app
COPY target/*-exe.jar ./app.jar
RUN apk --no-cache add tzdata curl  && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone
ENTRYPOINT ["java","-jar","./app.jar", "--port=80"]