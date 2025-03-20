FROM python:3.10.16-bullseye as cloudmapper

WORKDIR /app

RUN apt-get update -y
RUN apt-get install -y build-essential dnsutils autoconf automake libtool python3-tk jq awscli bash

COPY requirements.txt /app/
RUN pip install -r requirements.txt

ENV AWS_DEFAULT_REGION=us-east-1

COPY . /app/
COPY bin/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
