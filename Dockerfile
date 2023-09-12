FROM openjdk:21-slim as build-java

COPY . /src
RUN mkdir -p /build

RUN jdeps --generate-module-info /build /src/jsr305-3.0.2.jar && cd /build/jsr305 && javac /build/jsr305/module-info.java --patch-module jsr305=/src/jsr305-3.0.2.jar && jar xf /src/jsr305-3.0.2.jar && rm -f /build/jsr305/module-info.java
RUN javac --enable-preview --source 21 -p /build -d /build --module-source-path '/src/*/src/main/java' -m ax.xz.wireguard.noise,ax.xz.raw,ax.xz.raw.posix,ax.xz.wireguard
# extract jsr305 annotations to /build/jsr305

FROM alpine:3.18.3 as build-native
RUN --mount=type=cache,target=/var/cache/apk apk update && apk add cmake ninja build-base linux-headers

COPY . /build
WORKDIR /build

COPY --from=openjdk:21-bookworm /usr/local/openjdk-21/include /usr/local/openjdk-21/include
RUN JAVA_HOME=/usr/local/openjdk-21 cmake -DCMAKE_C_FLAGS="-static -fPIC" -DCMAKE_SHARED_LINKER_FLAGS="-static" -GNinja .
RUN ninja

FROM build-java as runtime
RUN mkdir /app
WORKDIR /app

COPY --from=build-java /build /app
COPY --from=build-native /build/libposix_raw.so /app
ENTRYPOINT ["java", "-server", "-Djdk.system.logger.level=FINE", "--enable-preview", "-p", ".", "-Djava.library.path=.", "-m", "ax.xz.wireguard/ax.xz.wireguard.cli.WireguardTunnelCLI", "/wireguard.conf"]