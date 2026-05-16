FROM alpine:3.20

COPY . trojan
RUN apk add --no-cache --virtual .build-deps \
        build-base \
        cmake \
        boost-dev \
        openssl-dev \
        mariadb-connector-c-dev \
    && (cd trojan && cmake -B build -DCMAKE_BUILD_TYPE=Release . \
        && cmake --build build -j "$(nproc)" \
        && strip -s build/trojan \
        && mv build/trojan /usr/local/bin) \
    && rm -rf trojan \
    && apk del .build-deps \
    && RUNTIME_BOOST=$(apk search -q 'boost*-system' | head -n1 | sed 's/-system$//') \
    && apk add --no-cache --virtual .trojan-rundeps \
        libstdc++ \
        "${RUNTIME_BOOST}-system" \
        "${RUNTIME_BOOST}-program_options" \
        mariadb-connector-c

WORKDIR /config
CMD ["trojan", "config.json"]
