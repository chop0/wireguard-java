FROM wireguard-java

RUN apt install -y wget iptables

RUN mkdir -p /usr/share/java
WORKDIR /usr/share/java
RUN wget https://repo1.maven.org/maven2/ch/qos/logback/logback-core/1.4.9/logback-core-1.4.9.jar
RUN wget https://repo1.maven.org/maven2/ch/qos/logback/logback-classic/1.4.9/logback-classic-1.4.9.jar
RUN wget https://repo1.maven.org/maven2/org/slf4j/slf4j-jdk-platform-logging/2.0.9/slf4j-jdk-platform-logging-2.0.9.jar
RUN wget https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar
WORKDIR /app

RUN mkdir -p ax.xz.wireguard/META-INF/services
RUN echo "org.slf4j.jdk.platform.logging.SLF4JSystemLoggerFinder" > 'ax.xz.wireguard/META-INF/services/java.lang.System$LoggerFinder'
EXPOSE 51820/udp
ENTRYPOINT ["/entrypoint_routing.sh",  "-p", "/app:/usr/share/java/logback-core-1.4.9.jar:/usr/share/java/logback-classic-1.4.9.jar:/usr/share/java/slf4j-jdk-platform-logging-2.0.9.jar:/usr/share/java/slf4j-api-2.0.9.jar"]
