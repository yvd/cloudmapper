#!/bin/bash

ACCOUNT=${ACCOUNT:-"prod"}
S3_BUCKET=${S3_BUCKET:-"prod-m-devops-reports"}
S3_BASE_PATH=${S3_BASE_PATH:-"border_police"}

echo "Collecting data for account: $ACCOUNT"
python cloudmapper.py collect --account $ACCOUNT

echo "Generating public data for account: $ACCOUNT"
python cloudmapper.py public --account $ACCOUNT > public_out.json

echo "Downloading vpn_ips.txt"
aws s3 cp s3://$S3_BUCKET/$S3_BASE_PATH/vpn_ips.txt .

echo "Generating Route 53 data for account: $ACCOUNT"
/app/r53_domains_automation.sh

echo "Generating HTML report with S3 integration"
python generate_html_report.py