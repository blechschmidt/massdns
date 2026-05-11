FROM alpine:3.20 AS build

RUN apk --no-cache add build-base git make
COPY . /src
RUN cd /src && make

FROM alpine:3.20

RUN mkdir -p /massdns/bin /massdns/lists
COPY --from=build /src/bin/massdns /massdns/bin/massdns
COPY lists/resolvers.txt /massdns/lists/resolvers.txt

ENV MASSDNS_BIN=/massdns/bin/massdns

ENTRYPOINT ["/massdns/bin/massdns"]
