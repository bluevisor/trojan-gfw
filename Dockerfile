FROM alpine:3.20 AS build

COPY . /src
RUN apk add --no-cache build-base cmake boost-dev openssl-dev mariadb-connector-c-dev \
 && cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /build -j "$(nproc)" \
 && strip -s /build/trojan

FROM alpine:3.20
RUN apk add --no-cache \
        libstdc++ \
        boost1.84-system \
        boost1.84-program_options \
        openssl \
        mariadb-connector-c
COPY --from=build /build/trojan /usr/local/bin/trojan

WORKDIR /config
CMD ["trojan", "config.json"]
