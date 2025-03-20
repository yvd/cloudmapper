#!/bin/bash
 
echo "Listing hosted zones"
aws route53 list-hosted-zones --output json | grep 'hostedzone' |  grep -oE 'hostedzone/[A-Z0-9]+' | cut -d '/' -f2 > zoneIDs

echo "Listing resource record sets"
cat zoneIDs | while read id; do aws route53 list-resource-record-sets --hosted-zone-id $id --output json | jq -r '.ResourceRecordSets[] | select(.Type == "A" or .Type == "CNAME")| { Domain_Name: .Name, "Routing traffic to": (if .AliasTarget.DNSName then .AliasTarget.DNSName else .ResourceRecords[].Value end)} | join(",")';done | grep -Fv '.int' > domains.csv

grep 'akamai-' domains.csv > akamai-domains.csv
grep -v 'akamai-' domains.csv > no-akamai-domains.csv

while IFS= read -r line; do
        domain=$(echo "$line" | cut -d ',' -f1 | sed 's/.$//') > /dev/null
        dns=$(echo "$line" | cut -d ',' -f2 | awk '{sub(/dualstack./,"")}1' | awk '{gsub("com\\.","com")}1') > /dev/null
        list_dns=$(echo "$line" | cut -d ',' -f2) > /dev/null
        
        ips=($(nslookup $domain | grep "Address:" | grep -v "#" | awk '{print $2}'))
        
        if [[ "$list_dns" == *"acm-validation"* ]]; then
                echo "$domain,$list_dns,ACM Validation" >> output_r53.csv
        elif [[ "$list_dns" =~ sendgrid ]]; then
                echo "$domain,$list_dns,Sendgrid" >> output_r53.csv
        elif [[ "$list_dns" =~ cloudfront ]]; then
                echo "$domain,$list_dns,CloudFront" >> output_r53.csv
        elif [[ "$list_dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "$domain,$list_dns,IP Address sendgrid?" >> output_r53.csv
        elif [[ "$list_dns" == *"domainconnect"* || "$list_dns" == *"domainkey"* ]]; then
                echo "$domain,$list_dns,Domain Control" >> output_r53.csv
		elif [[ "$list_dns" == *"edgekey.net"* ]]; then
                echo "$domain,$list_dns,Behind WAF" >> output_r53.csv
        else
                behind_vpn=false
                for ip in "${ips[@]}"; do
                        if grep -q "^${ip}$" vpn_ips.txt; then
                                echo "$domain,$list_dns,Behind VPN" >> output_r53.csv
                                behind_vpn=true
                                break
                        fi
                done
                if [ "$behind_vpn" = false ]; then
                        echo "$domain,$list_dns,Exposed" >> output_r53.csv
                fi
        fi
done < no-akamai-domains.csv

while IFS= read -r line; do
        domain=$(echo "$line" | cut -d ',' -f1 | sed 's/.$//') > /dev/null
		base_domain=${domain#akamai-}
		matching_line=$(grep "$base_domain" output_r53.csv)
        if [[ "$matching_line" == *"edgekey.net"* ]]; then
                echo "$line,WAF duplicate" >> output_r53.csv
        else
                echo "$line,Exposed" >> output_r53.csv
        fi
done < akamai-domains.csv
