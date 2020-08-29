FROM openjdk:8
VOLUME /tmp
EXPOSE 8090
ADD ./target/microservicios-zuul-0.0.1-SNAPSHOT.jar servicio-zuul.jar
ENTRYPOINT ["java","-jar","/servicio-zuul.jar"]