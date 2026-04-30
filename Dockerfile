FROM alpine:3.20 AS build

RUN apk --no-cache add build-base git make
COPY . /src
RUN cd /src && make

FROM alpine:3.20

RUN apk --no-cache add python3 py3-pip libstdc++ \
    && python3 -m venv /venv

ENV PATH="/venv/bin:${PATH}"

COPY app/requirements.txt /tmp/requirements.txt
RUN /venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

RUN mkdir -p /massdns/bin /massdns/lists
COPY --from=build /src/bin/massdns /massdns/bin/massdns
COPY lists/resolvers.txt /massdns/lists/resolvers.txt
COPY app/server.py /app/server.py
COPY app/templates /app/templates
COPY app/static /app/static

ENV PORT=8080 \
    MASSDNS_BIN=/massdns/bin/massdns \
    RESOLVERS=/massdns/lists/resolvers.txt \
    MAX_DOMAINS=10000

EXPOSE 8080

WORKDIR /app

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} --workers 2 --threads 4 --timeout 0 --access-logfile - server:app"]
