import json
from datetime import datetime
import argparse
import matplotlib.pyplot as plt
import io
import base64
from collections import Counter, defaultdict
import csv

def load_csv_data(file_path, old_file_path):
    """Load CSV data from the specified file path"""
    try:
        hostname_to_route53 = {}
        new_r53_set = set()
        old_r53_set = set()
        for i, file_path in enumerate([file_path, old_file_path]):
            old_data = False
            if i == 1:
                old_data = True
            with open(file_path, 'r') as f:
                csv_reader = csv.reader(f)
                # next(csv_reader)  # Skip header row
                for row in csv_reader:
                    if len(row) >= 3:  # Ensure row has at least 3 columns
                        route53_name = row[0]
                        hostname = row[1]
                        security_group = row[2]
                        if 'dualstack.' in hostname:
                            hostname = hostname.split('dualstack.')[1]
                        if hostname[-1] == '.':
                            hostname = hostname[:-1]
                        
                        # Initialize list for this hostname if it doesn't exist
                        if hostname not in hostname_to_route53:
                            hostname_to_route53[hostname] = []
                        if old_data:
                            old_r53_set.add(hostname)
                        else:
                            new_r53_set.add(hostname)
                        # Add the new mapping to the list
                        hostname_to_route53[hostname].append({
                            'name': route53_name,
                            'security_group': security_group
                        })
        deleted_r53_set = old_r53_set.difference(new_r53_set)
        new_r53_set = new_r53_set.difference(old_r53_set)
        del_r53_count = len(deleted_r53_set)
        new_r53_count = len(new_r53_set)
        for hostname in deleted_r53_set:
            for item in hostname_to_route53[hostname]:
                item['deleted'] = True
        for hostname in new_r53_set:
            for item in hostname_to_route53[hostname]:
                item['new'] = True
                    
        return hostname_to_route53, {
            'del_r53_count': del_r53_count,
            'new_r53_count': new_r53_count
        }
    except Exception as e:
        print(f"Error loading CSV data: {e}")
        return None

def load_json_data(file_path):
    """Load JSON data from the specified file path"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON data: {e}")
        return None

def generate_resource_type_chart(data):
    """Generate a pie chart for resource types"""
    resource_types = [item.get('type', 'unknown') for item in data]
    type_counts = Counter(resource_types)
    
    # Create pie chart
    plt.figure(figsize=(8, 6))
    plt.pie(type_counts.values(), labels=type_counts.keys(), autopct='%1.1f%%', startangle=90)
    plt.axis('equal')
    plt.title('Distribution of Resource Types')
    
    # Convert plot to base64 for embedding in HTML
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    
    return base64.b64encode(image_png).decode('utf-8')

def generate_port_distribution_chart(data):
    """Generate a bar chart for port distribution"""
    port_counter = Counter()
    
    for item in data:
        if 'ports' in item:
            ports = item['ports'].split(',')
            for port in ports:
                # Handle port ranges like 5021-5022
                if '-' in port:
                    start, end = port.split('-')
                    for p in range(int(start), int(end) + 1):
                        port_counter[str(p)] += 1
                else:
                    port_counter[port] += 1
    
    # Get top 10 ports
    top_ports = port_counter.most_common(10)
    ports = [p[0] for p in top_ports]
    counts = [p[1] for p in top_ports]
    
    plt.figure(figsize=(10, 6))
    plt.bar(ports, counts)
    plt.xlabel('Port')
    plt.ylabel('Count')
    plt.title('Top 10 Open Ports')
    plt.xticks(rotation=45)
    
    # Convert plot to base64 for embedding in HTML
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    
    return base64.b64encode(image_png).decode('utf-8')

def generate_security_group_chart(data):
    """Generate a bar chart for security groups"""
    sg_counter = Counter()
    
    for item in data:
        if 'public_sgs' in item:
            for sg_id, sg_info in item['public_sgs'].items():
                sg_name = sg_info.get('GroupName', 'Unknown')
                sg_counter[sg_name] += 1
    
    # Get top 10 security groups
    top_sgs = sg_counter.most_common(10)
    sg_names = [sg[0] for sg in top_sgs]
    counts = [sg[1] for sg in top_sgs]
    
    plt.figure(figsize=(12, 6))
    plt.bar(sg_names, counts)
    plt.xlabel('Security Group')
    plt.ylabel('Count')
    plt.title('Top 10 Security Groups')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    # Convert plot to base64 for embedding in HTML
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    
    return base64.b64encode(image_png).decode('utf-8')

def generate_html_report(data, output_file, old_data, route53_mapping=None, misc_info=None):
    """Generate an HTML report from the JSON data"""
    
    # Create sets of ARNs for comparison
    current_arns = {item.get('arn') for item in data if 'arn' in item}
    old_arns = {item.get('arn') for item in old_data if 'arn' in item} if old_data else set()
    
    # Generate charts
    resource_type_chart = generate_resource_type_chart(data)
    port_distribution_chart = generate_port_distribution_chart(data)
    security_group_chart = generate_security_group_chart(data)
    
    # Count resources by type
    resource_types = Counter([item.get('type', 'unknown') for item in data])
    
    # Group resources by type
    resources_by_type = defaultdict(list)
    for item in data:
        resource_type = item.get('type', 'unknown')
        resources_by_type[resource_type].append(item)
    
    # Create HTML content with added styles for new and removed resources
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AWS Public Resources Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 20px;
                color: #333;
            }}
            h1, h2, h3 {{
                color: #0066cc;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            .header {{
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 5px;
                margin-bottom: 20px;
                border-left: 5px solid #0066cc;
            }}
            .summary {{
                display: flex;
                flex-wrap: wrap;
                gap: 20px;
                margin-bottom: 30px;
            }}
            .summary-card {{
                background-color: #f8f9fa;
                border-radius: 5px;
                padding: 15px;
                flex: 1;
                min-width: 200px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }}
            .summary-card h3 {{
                margin-top: 0;
            }}
            .chart-container {{
                display: flex;
                flex-wrap: wrap;
                gap: 20px;
                margin-bottom: 30px;
            }}
            .chart {{
                background-color: white;
                border-radius: 5px;
                padding: 15px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                flex: 1;
                min-width: 300px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            .resource-section {{
                margin-bottom: 30px;
                background-color: white;
                border-radius: 5px;
                padding: 20px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }}
            .tag {{
                display: inline-block;
                background-color: #e9ecef;
                padding: 2px 8px;
                border-radius: 3px;
                margin: 2px;
                font-size: 0.9em;
            }}
            .port {{
                display: inline-block;
                background-color: #d1ecf1;
                color: #0c5460;
                padding: 2px 8px;
                border-radius: 3px;
                margin: 2px;
                font-size: 0.9em;
            }}
            .security-group {{
                display: inline-block;
                background-color: #f8d7da;
                color: #721c24;
                padding: 2px 8px;
                border-radius: 3px;
                margin: 2px;
                font-size: 0.9em;
            }}
            .footer {{
                text-align: center;
                margin-top: 30px;
                padding: 20px;
                background-color: #f8f9fa;
                border-radius: 5px;
            }}
            .accordion {{
                background-color: #f8f9fa;
                color: #444;
                cursor: pointer;
                padding: 18px;
                width: 100%;
                text-align: left;
                border: none;
                outline: none;
                transition: 0.4s;
                border-radius: 5px;
                margin-bottom: 5px;
                font-weight: bold;
            }}
            .active, .accordion:hover {{
                background-color: #e9ecef;
            }}
            .panel {{
                padding: 0 18px;
                background-color: white;
                max-height: 0;
                overflow: hidden;
                transition: max-height 0.2s ease-out;
                border-radius: 0 0 5px 5px;
                margin-bottom: 10px;
            }}
            .route53-mapping {{
                display: block;
                margin: 5px 0;
                padding: 5px;
                background-color: #f8f9fa;
                border-radius: 3px;
            }}
            .route53-name {{
                display: inline-block;
                background-color: #cce5ff;
                color: #004085;
                padding: 2px 8px;
                border-radius: 3px;
                margin: 2px;
                font-size: 0.9em;
            }}
            .new-resource {{
                background-color: #d4edda;
            }}
            .removed-resource {{
                background-color: #f8d7da;
            }}
            .route53-new {{
                background-color: #d4edda !important;
                border: 1px solid #c3e6cb;
            }}
            .route53-deleted {{
                background-color: #f8d7da !important;
                border: 1px solid #f5c6cb;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>AWS Public Resources Report</h1>
                <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Total resources: {len(data)}</p>
                <p>New resources: {len(current_arns - old_arns)}</p>
                <p>Removed resources: {len(old_arns - current_arns)}</p>
                <p>New Route 53 records: {misc_info['new_r53_count']}</p>
                <p>Removed Route 53 records: {misc_info['del_r53_count']}</p>
            </div>
            
            <div class="summary">
                <div class="summary-card">
                    <h3>Resource Types</h3>
                    <ul>
    """
    
    # Add resource type counts
    for resource_type, count in resource_types.items():
        html_content += f"<li><strong>{resource_type}:</strong> {count}</li>\n"
    
    html_content += """
                    </ul>
                </div>
                
                <div class="summary-card">
                    <h3>Security Insights</h3>
                    <ul>
    """
    
    # Count resources with specific ports
    http_count = sum(1 for item in data if 'ports' in item and ('80' in item['ports'].split(',') or '443' in item['ports'].split(',')))
    ssh_count = sum(1 for item in data if 'ports' in item and '22' in item['ports'].split(','))
    
    html_content += f"""
                        <li><strong>HTTP/HTTPS Exposed:</strong> {http_count}</li>
                        <li><strong>SSH Exposed:</strong> {ssh_count}</li>
                        <li><strong>Total Security Groups:</strong> {sum(len(item.get('public_sgs', {})) for item in data)}</li>
                    </ul>
                </div>
            </div>
            
            <div class="chart-container">
                <div class="chart">
                    <h3>Resource Type Distribution</h3>
                    <img src="data:image/png;base64,{resource_type_chart}" alt="Resource Type Distribution" style="width: 100%;">
                </div>
                
                <div class="chart">
                    <h3>Top 10 Open Ports</h3>
                    <img src="data:image/png;base64,{port_distribution_chart}" alt="Port Distribution" style="width: 100%;">
                </div>
            </div>
            
            <div class="chart">
                <h3>Top 10 Security Groups</h3>
                <img src="data:image/png;base64,{security_group_chart}" alt="Security Group Distribution" style="width: 100%;">
            </div>
    """
    
    # Update the Route 53 name rendering in all resource sections
    def generate_route53_cell(hostname, route53_mapping):
        html = "<td>"
        if route53_mapping and hostname in route53_mapping:
            for mapping in route53_mapping[hostname]:
                # Determine the CSS class based on new/deleted status
                css_class = ""
                if mapping.get('new'):
                    css_class = "route53-new"
                elif mapping.get('deleted'):
                    css_class = "route53-deleted"
                
                html += f'<div class="route53-mapping">'
                if mapping['name']:
                    html += f'<span class="route53-name {css_class}">{mapping["name"]}</span>'
                if mapping['security_group']:
                    html += f'<span class="security-group">{mapping["security_group"]}</span>'
                html += '</div>'
        html += "</td>"
        return html

    # Update all resource type sections to use the new route53 cell generator
    for resource_type, resources in resources_by_type.items():
        html_content += f"""
            <h2>{resource_type.upper()} Resources ({len(resources)})</h2>
            <button class="accordion">Show/Hide {resource_type.upper()} Resources</button>
            <div class="panel">
                <div class="resource-section">
                    <table>
                        <tr>
        """
        
        # Determine columns based on resource type
        if resource_type == 'ec2':
            html_content += """
                            <th>Instance ID</th>
                            <th>Public IP</th>
                            <th>Hostname</th>
                            <th>Route 53 Names</th>
                            <th>Open Ports</th>
                            <th>Security Groups</th>
                            <th>Tags</th>
            """
        elif resource_type == 'elbv2':
            html_content += """
                            <th>Load Balancer</th>
                            <th>Hostname</th>
                            <th>Route 53 Names</th>
                            <th>Open Ports</th>
                            <th>Security Groups</th>
            """
        elif resource_type == 'apigateway':
            html_content += """
                            <th>API ID</th>
                            <th>Hostname</th>
                            <th>Route 53 Names</th>
                            <th>Open Ports</th>
            """
        elif resource_type == 'cloudfront':
            html_content += """
                            <th>Distribution ID</th>
                            <th>Hostname</th>
                            <th>Route 53 Names</th>
                            <th>Open Ports</th>
            """
        else:
            html_content += """
                            <th>ARN</th>
                            <th>Hostname</th>
                            <th>Route 53 Names</th>
                            <th>Open Ports</th>
                            <th>Details</th>
            """
        
        html_content += "</tr>"
        
        # Add rows for current resources
        for resource in resources:
            resource_arn = resource.get('arn')
            row_class = ''
            if resource_arn:
                if resource_arn in old_arns:
                    row_class = ''  # unchanged
                else:
                    row_class = 'new-resource'  # new resource
            
            html_content += f'<tr class="{row_class}">'
            
            if resource_type == 'ec2':
                instance_id = resource['arn'].split('/')[-1] if 'arn' in resource else 'Unknown'
                html_content += f"<td>{instance_id}</td>"
                html_content += f"<td>{resource.get('public_ip', 'N/A')}</td>"
                html_content += f"<td>{resource.get('hostname', 'N/A')}</td>"
                html_content += generate_route53_cell(resource.get('hostname'), route53_mapping)
                
                # Add ports
                html_content += "<td>"
                if 'ports' in resource:
                    for port in resource['ports'].split(','):
                        html_content += f'<span class="port">{port}</span> '
                html_content += "</td>"
                
                # Add security groups
                html_content += "<td>"
                if 'public_sgs' in resource:
                    for sg_id, sg_info in resource['public_sgs'].items():
                        sg_name = sg_info.get('GroupName', 'Unknown')
                        html_content += f'<span class="security-group">{sg_name}</span> '
                html_content += "</td>"
                
                # Add tags
                html_content += "<td>"
                if 'tags' in resource:
                    for tag in resource['tags']:
                        html_content += f'<span class="tag">{tag.get("Key", "")}: {tag.get("Value", "")}</span> '
                html_content += "</td>"
                
            elif resource_type == 'elbv2':
                lb_name = resource['arn'].split('/')[-2] if 'arn' in resource else 'Unknown'
                html_content += f"<td>{lb_name}</td>"
                html_content += f"<td>{resource.get('hostname', 'N/A')}</td>"
                html_content += generate_route53_cell(resource.get('hostname'), route53_mapping)
                
                # Add ports
                html_content += "<td>"
                if 'ports' in resource:
                    for port in resource['ports'].split(','):
                        html_content += f'<span class="port">{port}</span> '
                html_content += "</td>"
                
                # Add security groups
                html_content += "<td>"
                if 'public_sgs' in resource:
                    for sg_id, sg_info in resource['public_sgs'].items():
                        sg_name = sg_info.get('GroupName', 'Unknown')
                        html_content += f'<span class="security-group">{sg_name}</span> '
                html_content += "</td>"
                
            elif resource_type == 'apigateway':
                api_id = resource['arn'] if 'arn' in resource else 'Unknown'
                html_content += f"<td>{api_id}</td>"
                html_content += f"<td>{resource.get('hostname', 'N/A')}</td>"
                html_content += generate_route53_cell(resource.get('hostname'), route53_mapping)
                
                # Add ports
                html_content += "<td>"
                if 'ports' in resource:
                    for port in resource['ports'].split(','):
                        html_content += f'<span class="port">{port}</span> '
                html_content += "</td>"
                
            elif resource_type == 'cloudfront':
                dist_id = resource['arn'].split('/')[-1] if 'arn' in resource else 'Unknown'
                html_content += f"<td>{dist_id}</td>"
                html_content += f"<td>{resource.get('hostname', 'N/A')}</td>"
                html_content += generate_route53_cell(resource.get('hostname'), route53_mapping)
                
                # Add ports
                html_content += "<td>"
                if 'ports' in resource:
                    for port in resource['ports'].split(','):
                        html_content += f'<span class="port">{port}</span> '
                html_content += "</td>"
                
            else:
                html_content += f"<td>{resource.get('arn', 'N/A')}</td>"
                html_content += f"<td>{resource.get('hostname', 'N/A')}</td>"
                html_content += generate_route53_cell(resource.get('hostname'), route53_mapping)
                
                # Add ports
                html_content += "<td>"
                if 'ports' in resource:
                    for port in resource['ports'].split(','):
                        html_content += f'<span class="port">{port}</span> '
                html_content += "</td>"
                
                # Add a generic details column
                html_content += "<td>"
                for key, value in resource.items():
                    if key not in ['arn', 'hostname', 'ports', 'type', 'account']:
                        html_content += f'<span class="tag">{key}: {value}</span> '
                html_content += "</td>"
            
            html_content += "</tr>"
        
        # Add rows for removed resources
        removed_resources = old_arns - current_arns
        if removed_resources:
            old_resources_by_type = defaultdict(list)
            for item in old_data:
                if item.get('type') == resource_type and item.get('arn') in removed_resources:
                    old_resources_by_type[resource_type].append(item)
            
            for resource in old_resources_by_type[resource_type]:
                html_content += '<tr class="removed-resource">'
                
                if resource_type == 'ec2':
                    instance_id = resource['arn'].split('/')[-1] if 'arn' in resource else 'Unknown'
                    html_content += f"<td>{instance_id}</td>"
                    html_content += f"<td>{resource.get('public_ip', 'N/A')}</td>"
                    html_content += f"<td>{resource.get('hostname', 'N/A')}</td>"
                    html_content += generate_route53_cell(resource.get('hostname'), route53_mapping)
                    
                    # Add ports
                    html_content += "<td>"
                    if 'ports' in resource:
                        for port in resource['ports'].split(','):
                            html_content += f'<span class="port">{port}</span> '
                    html_content += "</td>"
                    
                    # Add security groups
                    html_content += "<td>"
                    if 'public_sgs' in resource:
                        for sg_id, sg_info in resource['public_sgs'].items():
                            sg_name = sg_info.get('GroupName', 'Unknown')
                            html_content += f'<span class="security-group">{sg_name}</span> '
                    html_content += "</td>"
                    
                    # Add tags
                    html_content += "<td>"
                    if 'tags' in resource:
                        for tag in resource['tags']:
                            html_content += f'<span class="tag">{tag.get("Key", "")}: {tag.get("Value", "")}</span> '
                    html_content += "</td>"
                
                elif resource_type == 'elbv2':
                    lb_name = resource['arn'].split('/')[-2] if 'arn' in resource else 'Unknown'
                    html_content += f"<td>{lb_name}</td>"
                    html_content += f"<td>{resource.get('hostname', 'N/A')}</td>"
                    html_content += generate_route53_cell(resource.get('hostname'), route53_mapping)
                    
                    # Add ports
                    html_content += "<td>"
                    if 'ports' in resource:
                        for port in resource['ports'].split(','):
                            html_content += f'<span class="port">{port}</span> '
                    html_content += "</td>"
                    
                    # Add security groups
                    html_content += "<td>"
                    if 'public_sgs' in resource:
                        for sg_id, sg_info in resource['public_sgs'].items():
                            sg_name = sg_info.get('GroupName', 'Unknown')
                            html_content += f'<span class="security-group">{sg_name}</span> '
                    html_content += "</td>"
                
                elif resource_type in ['apigateway', 'cloudfront']:
                    id_field = resource['arn'].split('/')[-1] if 'arn' in resource else 'Unknown'
                    html_content += f"<td>{id_field}</td>"
                    html_content += f"<td>{resource.get('hostname', 'N/A')}</td>"
                    html_content += generate_route53_cell(resource.get('hostname'), route53_mapping)
                    
                    # Add ports
                    html_content += "<td>"
                    if 'ports' in resource:
                        for port in resource['ports'].split(','):
                            html_content += f'<span class="port">{port}</span> '
                    html_content += "</td>"
                
                else:
                    html_content += f"<td>{resource.get('arn', 'N/A')}</td>"
                    html_content += f"<td>{resource.get('hostname', 'N/A')}</td>"
                    html_content += generate_route53_cell(resource.get('hostname'), route53_mapping)
                    
                    # Add ports
                    html_content += "<td>"
                    if 'ports' in resource:
                        for port in resource['ports'].split(','):
                            html_content += f'<span class="port">{port}</span> '
                    html_content += "</td>"
                    
                    # Add a generic details column
                    html_content += "<td>"
                    for key, value in resource.items():
                        if key not in ['arn', 'hostname', 'ports', 'type', 'account']:
                            html_content += f'<span class="tag">{key}: {value}</span> '
                    html_content += "</td>"
                
                html_content += "</tr>"
        
        html_content += """
                    </table>
                </div>
            </div>
        """
    
    # Add footer and JavaScript for accordion
    html_content += """
            <div class="footer">
                <p>This report was generated automatically. For security concerns, please contact the security team.</p>
                <div class="legend">
                    <p><span style="background-color: #d4edda; padding: 2px 8px;">New Resource</span></p>
                    <p><span style="background-color: #f8d7da; padding: 2px 8px;">Removed Resource</span></p>
                    <p><span style="background-color: #d4edda; padding: 2px 8px; border: 1px solid #c3e6cb;">New Route 53 Record</span></p>
                    <p><span style="background-color: #f8d7da; padding: 2px 8px; border: 1px solid #f5c6cb;">Removed Route 53 Record</span></p>
                </div>
            </div>
        </div>
        
        <script>
            var acc = document.getElementsByClassName("accordion");
            var i;
            
            for (i = 0; i < acc.length; i++) {
                acc[i].addEventListener("click", function() {
                    this.classList.toggle("active");
                    var panel = this.nextElementSibling;
                    if (panel.style.maxHeight) {
                        panel.style.maxHeight = null;
                    } else {
                        panel.style.maxHeight = panel.scrollHeight + "px";
                    }
                });
            }
        </script>
    </body>
    </html>
    """
    
    # Write HTML to file
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    print(f"HTML report generated: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Generate an HTML report from CloudMapper JSON data, visualizing AWS public resources with optional Route 53 mapping and resource change tracking.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Generate basic report with default filenames
    python generate_html_report.py

    # Generate report with custom input/output files
    python generate_html_report.py -i current.json -o report.html

    # Generate report with Route 53 mapping
    python generate_html_report.py -r route53_mapping.csv

    # Generate report with change tracking
    python generate_html_report.py -i current.json -p previous.json -r current_r53.csv -rpre previous_r53.csv
        """
    )

    # Input/Output arguments
    io_group = parser.add_argument_group('Input/Output Options')
    io_group.add_argument('--input', '-i',
                         default='stage_public.json',
                         help='Path to the current JSON file containing AWS resource data (default: stage_public.json)')
    io_group.add_argument('--output', '-o',
                         default='aws_public_resources_report.html',
                         help='Path for the output HTML report (default: aws_public_resources_report.html)')

    # Change tracking arguments
    change_group = parser.add_argument_group('Change Tracking Options')
    change_group.add_argument('--input_old', '-p',
                             default='stage_public.json',
                             help='Path to the previous JSON file for change tracking (default: stage_public.json)')

    # Route 53 mapping arguments
    route53_group = parser.add_argument_group('Route 53 Mapping Options')
    route53_group.add_argument('--route53', '-r',
                              help='Path to CSV file containing current Route 53 mappings. Format: Route53Name,Hostname,SecurityGroup')
    route53_group.add_argument('--route53_old', '-rpre',
                              help='Path to CSV file containing previous Route 53 mappings for change tracking')
    
    args = parser.parse_args()
    
    # Load JSON data
    data = load_json_data(args.input)
    if not data:
        return

    old_json = []
    if args.input_old:
        old_json = load_json_data(args.input_old)

    # Load Route 53 mapping if provided
    route53_mapping = None
    if args.route53:
        route53_mapping, misc_info = load_csv_data(args.route53, args.route53_old)
    
    # Generate HTML report
    generate_html_report(data, args.output, old_json, route53_mapping, misc_info)

if __name__ == "__main__":
    main() 