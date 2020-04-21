FROM jfloff/alpine-python:3.8-slim
COPY app .

RUN addgroup -g 1001 -S ntpgroup
RUN adduser -S --ingroup ntpgroup --uid 1001 ntpuser

RUN apk update
RUN pip install flask gunicorn psycopg2

EXPOSE 5000
USER ntpuser
ENTRYPOINT ["gunicorn"]
CMD ["-w", "1", "-b", "0.0.0.0:5000" ,"ntp:app"]
