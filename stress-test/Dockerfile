FROM openjdk:21-slim as profiler-build
RUN apt update && apt install -y build-essential git
RUN git clone https://github.com/async-profiler/async-profiler /src
RUN cd /src && make
RUN mkdir /out && cp /src/build/lib/* /out/ && cp /src/build/bin/* /out/

FROM wireguard-java

RUN apt install -y iptables iperf3
COPY --from=profiler-build /out/libasyncProfiler.so /libasyncProfiler.so

EXPOSE 51820/udp
ENTRYPOINT ["/entrypoint_routing.sh"]
