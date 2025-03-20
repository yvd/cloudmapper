FROM python:3.10.16-bullseye as cloudmapper

WORKDIR /app

RUN apt-get update -y
RUN apt-get install -y build-essential dnsutils autoconf automake libtool python3-tk jq awscli bash cron

COPY requirements.txt /app/
RUN pip install -r requirements.txt

ENV AWS_DEFAULT_REGION=us-east-1

COPY . /app/
COPY bin/entrypoint.sh /app/entrypoint.sh
COPY bin/start.sh /app/start.sh
COPY bin/r53_domains_automation.sh /app/r53_domains_automation.sh
COPY config.json /app/config.json

# Set up cron job
RUN echo "0 0 * * * /app/entrypoint.sh prod >> /var/log/cron.log 2>&1" > /etc/cron.d/cloudmapper-cron
RUN chmod 0644 /etc/cron.d/cloudmapper-cron
RUN crontab /etc/cron.d/cloudmapper-cron
RUN touch /var/log/cron.log

ENTRYPOINT ["/app/start.sh"]
