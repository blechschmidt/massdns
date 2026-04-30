FROM alpine:edge

COPY . /massdns

RUN apk --no-cache --virtual .build-deps add git build-base \
   && cd /massdns && make && apk del .build-deps


WORKDIR /massdns/

ENTRYPOINT ["./bin/massdns"]
