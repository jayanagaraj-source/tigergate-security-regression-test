# Runtime image for the LOC fixture.
FROM python:3.12-slim

WORKDIR /srv/app
COPY app/ /srv/app/
USER 1000
HEALTHCHECK CMD ["python", "-c", "print('ok')"]
CMD ["python", "service.py"]
