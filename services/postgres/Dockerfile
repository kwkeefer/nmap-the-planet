FROM postgres:alpine

ENV POSTGRES_USER = "postgres"
ENV POSTGRES_PASSWORD = "password!"
ENV POSTGRES_DB = "ntp"


ENV USER=docker
ENV UID=12345
ENV GID=23456

RUN addgroup docker
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "$(pwd)" \
    --ingroup "$USER" \
    --no-create-home \
    --uid "$UID" \
    "$USER"

COPY ./init-user-db.sh /docker-entrypoint-initdb.d

USER docker
