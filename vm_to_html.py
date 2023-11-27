import json
import sys


def json_to_html_with_tabs(json_file, output_file):
    # Load JSON data
    with open(json_file, "r") as file:
        data = json.load(file)

    # Start HTML content
    html_content = """
    <html>
    <head>
        <title>Docker Image Scan Report</title>
        <link href="https://fonts.googleapis.com/css2?family=Jost:wght@400;500&display=swap" rel="stylesheet">
        <style>
            body {
                font-family: 'Consolas', 'Courier New', monospace;
                margin: 0;
                padding-top: 20px;
            }
            .tab {
                overflow: hidden;
                border: 1px solid #ccc;
                background-color: #f1f1f1;
            }
            .tab button {
                background-color: inherit;
                float: left;
                border: none;
                outline: none;
                cursor: pointer;
                padding: 14px 16px;
                transition: 0.3s;
                font-size: 18px; /* Larger font size */
                font-weight: bold; /* Bolder font */
            }
            .tab button:hover { background-color: #ddd; }
            .tab button.active { background-color: #ccc; }
            .tabcontent {
                display: none;
                padding: 20px;
                border: 1px solid #ccc;
                border-top: none;
                margin: 10px;
            }
            table {
                border-collapse: collapse;
                width: 100%;
                margin: 10px;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }
            th { background-color: #f2f2f2; }
            .Critical { color: #800080; font-weight: bold; }
            .High { color: #ff0000; font-weight: bold; }
            .Medium { color: #ffa500; font-weight: bold; }
            .Low { color: #9acd32; font-weight: bold; }
            .Negligible { color: #808080; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="tab">
            <button class="tablinks" onclick="openTab(event, 'Info')">Info</button>
            <button class="tablinks" onclick="openTab(event, 'Policies')">Policies</button>
            <button class="tablinks" onclick="openTab(event, 'Vulnerabilities')">Vulnerabilities</button>
            <button class="tablinks" onclick="openTab(event, 'Packages')">Packages</button>
        </div>
    """

    # Function for tab switching
    html_content += """
        <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }
        </script>
    """

    # Info tab (combined Metadata and Info)
    html_content += "<div id='Info' class='tabcontent'>"
    combined_info = {**data.get("metadata", {}), **data.get("info", {})}
    for key, value in combined_info.items():
        if key == "resultURL":
            # Making resultURL a clickable link
            html_content += f"<p><strong>{key.capitalize()}:</strong> <a href='{value}' target='_blank'>{value}</a></p>"
        else:
            html_content += f"<p><strong>{key.capitalize()}:</strong> {value}</p>"
    html_content += "</div>"

    # Policies tab
    html_content += "<div id='Policies' class='tabcontent'><h3>Policies</h3>"
    html_content += "<h4>Policy Details</h4><table><tr><th>Policy Name</th><th>Type</th><th>Bundle Details</th><th>Failures Count</th></tr>"
    for policy in data["policies"]["list"]:
        policy_name = policy["name"]
        policy_type = policy["type"]
        failures_count = policy["failuresCount"]
        # Processing bundle details
        bundle_details = "<ul>"
        for bundle in policy["bundle"]:
            bundle_name = bundle["name"]
            bundle_type = bundle["type"]
            bundle_failures_count = bundle["failuresCount"]
            bundle_details += f"<li><strong>{bundle_name}</strong> ({bundle_type}), Failures: {bundle_failures_count}</li>"
        bundle_details += "</ul>"
        html_content += f"<tr><td>{policy_name}</td><td>{policy_type}</td><td>{bundle_details}</td><td>{failures_count}</td></tr>"
    html_content += "</table>"
    html_content += "</div>"

    # Vulnerabilities tab
    html_content += (
        "<div id='Vulnerabilities' class='tabcontent'><h3>Vulnerabilities</h3>"
    )
    # Summary by Severity
    html_content += (
        "<h4>Summary by Severity</h4><table><tr><th>Severity</th><th>Total</th></tr>"
    )
    for severity in data["vulnerabilities"]["bySeverity"]:
        severity_label = severity["severity"]["label"]
        severity_total = severity["total"]
        severity_class = severity_label.replace(" ", "")  # Remove spaces for CSS class
        html_content += f"<tr><td class='{severity_class}'>{severity_label}</td><td>{severity_total}</td></tr>"
    html_content += "</table>"

    # Detailed List of Vulnerabilities
    html_content += "<h4>Detailed List of Vulnerabilities</h4><table><tr><th>Name</th><th>Severity</th><th>CVSS Score</th><th>CVSS Vector</th><th>Disclosure Date</th><th>Source URL</th><th>Affected Packages</th></tr>"
    for vuln in data["vulnerabilities"]["list"]:
        name = vuln["name"]
        severity = vuln["severity"]["label"]
        cvss_score = vuln["cvssScore"]["value"]["score"]
        cvss_vector = vuln["cvssScore"]["value"]["vector"]
        source_url = vuln["severity"].get("sourceUrl", "Not Available")
        disclosure_date = vuln["disclosureDate"]
        affected_packages = ", ".join(vuln["affectedPackages"])
        severity_class = severity.replace(" ", "")  # Remove spaces for CSS class
        # Ensure source URL is clickable
        source_url_html = f'<a href="{source_url}" target="_blank">{source_url}</a>' if source_url != "Not Available" else "Not Available"
        html_content += f"<tr><td>{name}</td><td class='{severity_class}'>{severity}</td><td>{cvss_score}</td><td>{cvss_vector}</td><td>{disclosure_date}</td><td>{source_url_html}</td><td>{affected_packages}</td></tr>"
    html_content += "</table>"
    html_content += "</div>"

    # Packages tab
    html_content += "<div id='Packages' class='tabcontent'><h3>Packages</h3>"
    html_content += "<h4>Package Details</h4><table><tr><th>Package Name</th><th>Version</th><th>Suggested Fix</th><th>Severity Summary</th><th>Vulnerabilities</th></tr>"
    for package in data["packages"]["list"]:
        package_name = package["name"]
        package_version = package["version"]
        suggested_fix = package.get("suggestedFix", "N/A")  # Include the suggested fix, with "N/A" as a default
        severity_summary = ", ".join(
            [
                f"{severity['severity']['label']}: {severity['total']}"
                for severity in package["vulnsBySeverity"]
                if severity["total"] > 0
            ]
        )
        vuln_details = "<ul>"
        for vuln in package["vulnerabilities"]:
            vuln_name = vuln["name"]
            vuln_severity = vuln["severity"]["label"]
            vuln_severity_class = vuln_severity.replace(" ", "")  # For CSS class
            vuln_score = vuln["cvssScore"]["value"]["score"]
            vuln_details += f"<li class='{vuln_severity_class}'><strong>{vuln_name}</strong> - {vuln_severity} (Score: {vuln_score})</li>"
        vuln_details += "</ul>"
        html_content += f"<tr><td>{package_name}</td><td>{package_version}</td><td>{suggested_fix}</td><td>{severity_summary}</td><td>{vuln_details}</td></tr>"
    html_content += "</table>"
    html_content += "</div>"


    # Closing HTML tags
    html_content += """
    <script>
    document.getElementsByClassName('tablinks')[0].click();
    </script>
    </body>
    </html>
    """

    # Writing the HTML content to the output file
    with open(output_file, "w") as file:
        file.write(html_content)


# Main script execution
if len(sys.argv) != 3:
    print("Usage: python script.py <input_json_file> <output_html_file>")
    sys.exit(1)

input_json_file = sys.argv[1]
output_html_file = sys.argv[2]

# Generating the HTML file
json_to_html_with_tabs(input_json_file, output_html_file)
