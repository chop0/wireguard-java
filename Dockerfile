FROM openjdk:21-slim as build-java

COPY ./jsr305-3.0.2.jar /src/jsr305-3.0.2.jar
COPY ./ax.xz.raw/src/main/java /src/ax.xz.raw/src/main/java
COPY ./ax.xz.raw.posix/src/main/java /src/ax.xz.raw.posix/src/main/java
COPY ./ax.xz.wireguard/src/main/java /src/ax.xz.wireguard/src/main/java
COPY ./ax.xz.wireguard.noise/src/main/java /src/ax.xz.wireguard.noise/src/main/java
RUN mkdir -p /build

RUN jdeps --generate-module-info /build /src/jsr305-3.0.2.jar && cd /build/jsr305 && javac /build/jsr305/module-info.java --patch-module jsr305=/src/jsr305-3.0.2.jar && jar xf /src/jsr305-3.0.2.jar && rm -f /build/jsr305/module-info.java
RUN javac --enable-preview --release 21 -p /build -d /build --module-source-path '/src/*/src/main/java' -m ax.xz.raw,ax.xz.raw.posix,ax.xz.wireguard,ax.xz.wireguard.noise

FROM alpine:3.18.3 as build-native
RUN --mount=type=cache,target=/var/cache/apk apk update && apk add cmake ninja build-base linux-headers

COPY ./CMakeLists.txt /build/CMakeLists.txt
COPY ./ax.xz.raw.posix/src/main/c /build/ax.xz.raw.posix/src/main/c
COPY ./ax.xz.wireguard.noise/src/main/c /build/ax.xz.wireguard.noise/src/main/c
WORKDIR /build

COPY --from=openjdk:21-slim /usr/local/openjdk-21/include /usr/local/openjdk-21/include
RUN JAVA_HOME=/usr/local/openjdk-21 cmake -DCMAKE_C_FLAGS="-nostdlib -l:libc.a" -GNinja .
RUN ninja -j$(nproc) libpoly1305-donna.so libposix_raw.so libchacha.so

FROM openjdk:21-slim as profiler-build
RUN apt update && apt install -y cmake make gcc g++ git
RUN git clone https://github.com/async-profiler/async-profiler /src
RUN cd /src && make -j$(nproc)
RUN mkdir /out && cp /src/build/lib/* /out/ && cp /src/build/bin/* /out/

FROM openjdk:21-slim as runtime
RUN apt update && apt install -y iproute2 iptables iperf3 wget

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
COPY --from=build-native /build/libposix_raw.so .
COPY --from=build-native /build/libpoly1305-donna.so .
COPY --from=build-native /build/libchacha.so .
COPY --from=profiler-build /out/libasyncProfiler.so /libasyncProfiler.so

COPY ./run.sh /app/run.sh
ENTRYPOINT ["/app/run.sh", "-cp", "/app:/usr/share/java/logback-core-1.4.9.jar:/usr/share/java/logback-classic-1.4.9.jar:/usr/share/java/slf4j-jdk-platform-logging-2.0.9.jar:/usr/share/java/slf4j-api-2.0.9.jar"]