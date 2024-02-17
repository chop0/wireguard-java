FROM openjdk:21-slim as build-java

COPY ./ax.xz.raw/src/main/java /src/ax.xz.raw/src/main/java
COPY ./ax.xz.wireguard/src/main/java /src/ax.xz.wireguard/src/main/java
COPY ./ax.xz.wireguard.cli/src/main/java /src/ax.xz.wireguard.cli/src/main/java
RUN mkdir -p /build

RUN javac --enable-preview --release 21 -p /build -d /build --module-source-path '/src/*/src/main/java' -m ax.xz.raw,ax.xz.wireguard,ax.xz.wireguard.cli

FROM build-java AS build-jar
WORKDIR /build
RUN echo "Class-Path: wireguard-raw.jar wireguard-core.jar" >> Manifest.txt
RUN jar --create --file /wireguard-core.jar -C ax.xz.wireguard .
RUN jar --create --file /wireguard-cli.jar -m Manifest.txt --main-class ax.xz.wireguard.cli.WireguardTunnelCLI -m Manifest.txt -C ax.xz.wireguard.cli .
RUN jar --create --file /wireguard-raw.jar -C ax.xz.raw .

FROM scratch AS binaries
COPY --from=build-jar /*.jar /

FROM openjdk:21-slim as profiler-build
RUN apt update && apt install -y cmake make gcc g++ git
RUN git clone https://github.com/async-profiler/async-profiler /src
RUN cd /src && make -j$(nproc)
RUN mkdir /out && cp /src/build/lib/* /out/ && cp /src/build/bin/* /out/

FROM openjdk:21-slim as runtime
RUN apt update && apt install -y iproute2 iptables iperf3 wget inotify-tools iputils-ping curl

WORKDIR /app

RUN mkdir -p /usr/share/java
WORKDIR /usr/share/java
RUN wget https://repo1.maven.org/maven2/ch/qos/logback/logback-core/1.4.9/logback-core-1.4.9.jar
RUN wget https://repo1.maven.org/maven2/ch/qos/logback/logback-classic/1.4.9/logback-classic-1.4.9.jar
RUN wget https://repo1.maven.org/maven2/org/slf4j/slf4j-jdk-platform-logging/2.0.9/slf4j-jdk-platform-logging-2.0.9.jar
RUN wget https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar
WORKDIR /app

RUN mkdir -p ax.xz.wireguard/META-INF/services
RUN echo "org.slf4j.jdk.platform.logging.SLF4JSystemLoggerFinder" > 'ax.xz.wireguard/META-INF/services/java.lang.System$LoggerFinder'

COPY --from=build-java /build .
COPY --from=profiler-build /out/libasyncProfiler.so /libasyncProfiler.so

COPY ./run.sh /app/run.sh
ENTRYPOINT ["/app/run.sh",  "-p", "/app:/usr/share/java/logback-core-1.4.9.jar:/usr/share/java/logback-classic-1.4.9.jar:/usr/share/java/slf4j-jdk-platform-logging-2.0.9.jar:/usr/share/java/slf4j-api-2.0.9.jar"]