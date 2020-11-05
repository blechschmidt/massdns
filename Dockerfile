FROM alpine:edge

RUN apk --update --no-cache --virtual .build-deps add git build-base \
   && git clone --depth=1 https://github.com/blechschmidt/massdns.git \
   && cd massdns && make && apk del .build-deps

WORKDIR /massdns/

ENTRYPOINT ["./bin/massdns"]
