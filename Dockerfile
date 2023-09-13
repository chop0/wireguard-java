FROM openjdk:21-slim as build-java

COPY . /src
RUN mkdir -p /build

RUN jdeps --generate-module-info /build /src/jsr305-3.0.2.jar && cd /build/jsr305 && javac /build/jsr305/module-info.java --patch-module jsr305=/src/jsr305-3.0.2.jar && jar xf /src/jsr305-3.0.2.jar && rm -f /build/jsr305/module-info.java
RUN javac --enable-preview --source 21 -p /build -d /build --module-source-path '/src/*/src/main/java' -m ax.xz.wireguard.noise,ax.xz.raw,ax.xz.raw.posix,ax.xz.wireguard

FROM alpine:3.18.3 as build-native
RUN --mount=type=cache,target=/var/cache/apk apk update && apk add cmake ninja build-base linux-headers

COPY . /build
WORKDIR /build

COPY --from=openjdk:21-bookworm /usr/local/openjdk-21/include /usr/local/openjdk-21/include
RUN JAVA_HOME=/usr/local/openjdk-21 cmake -DCMAKE_C_FLAGS="-nostdlib -l:libc.a" -GNinja .
RUN ninja -j$(nproc) libposix_raw.so

FROM openjdk:21-slim as profiler-build
RUN apt update && apt install -y build-essential git
RUN git clone https://github.com/async-profiler/async-profiler /src
RUN cd /src && make
RUN mkdir /out && cp /src/build/lib/* /out/ && cp /src/build/bin/* /out/

FROM openjdk:21-slim as runtime
RUN --mount=type=cache,target=/var/cache/apt apt update && apt install -y iproute2 iptables iperf3 iputils-ping net-tools tcpdump

RUN mkdir /app
WORKDIR /app

COPY --from=build-java /build .
COPY --from=build-native /build/libposix_raw.so .
COPY --from=profiler-build /out/libasyncProfiler.so /libasyncProfiler.so

COPY ./run.sh /app/run.sh
ENTRYPOINT ["/app/run.sh"]
