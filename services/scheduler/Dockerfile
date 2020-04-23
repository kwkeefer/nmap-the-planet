FROM jfloff/alpine-python:3.8-slim
COPY app .

RUN addgroup -g 1001 -S ntpgroup
RUN adduser -S --ingroup ntpgroup --uid 1001 ntpuser

RUN pip install flask gunicorn retrying requests

EXPOSE 5000
USER ntpuser
ENTRYPOINT ["gunicorn"]
CMD ["-w", "1", "-b", "0.0.0.0:5000" ,"scheduler:app"]
