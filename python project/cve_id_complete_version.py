import os
import re
import json
import webbrowser
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from docx import Document
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
from fpdf import FPDF
import time
import requests
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import bleach


# Set up Selenium WebDriver
driver = webdriver.Firefox()  # change this parameter if you have different browser

# Declaring url patterns for websites for further use
nvd_url_pattern = "https://nvd.nist.gov/vuln/detail/{cve_id}"
exploit_db_url_pattern = "https://www.exploit-db.com/search?cve={cve_id}"
cve_url_pattern = "https://www.cvedetails.com/cve/{cve_id}/"
vulmon_url_pattern = "https://vulmon.com/vulnerabilitydetails?qid={cve_id}&scoretype=cvssv3"

# Define API URL for fetching CVE information
cve_api_url = "https://cve.circl.lu/api/cve/"

# Function to fetch CVE information from the API
def fetch_cve_info(cve_id):
    api_url = f"{cve_api_url}{cve_id}"
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            cve_info = response.json()
            return cve_info
        else:
            print(f"Error fetching CVE information: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Error fetching CVE information: {e}")
        return None

# Function to open reference sites
def open_references(cve_id):
    # Construct URLs based on the CVE ID
    nvd_url = nvd_url_pattern.format(cve_id=cve_id)
    exploit_db_url = exploit_db_url_pattern.format(cve_id=cve_id)
    cve_url = cve_url_pattern.format(cve_id=cve_id)
    vulmon_url = vulmon_url_pattern.format(cve_id=cve_id)

    # Open tabs for NVD, Exploit-DB, CVE Details, and Vulmon
    webbrowser.open_new_tab(nvd_url)
    webbrowser.open_new_tab(exploit_db_url)
    webbrowser.open_new_tab(cve_url)
    webbrowser.open_new_tab(vulmon_url)

# Function to generate PDF report
def generate_pdf(cve_info, cve_id):
    if cve_info:
        try:
            # Create PDF document
            doc = SimpleDocTemplate(f"{cve_id}.pdf", pagesize=letter)
            styles = getSampleStyleSheet()

            # Define style for content
            normal_style = styles['Normal']

            # Create list to store content paragraphs
            content = []

            # Add title to the content
            title_text = f"<b>CVE Information for {cve_id}</b>\n\n"
            content.append(Paragraph(title_text, styles['Title']))

            # Add each key-value pair from cve_info as a paragraph to content
            for key, value in cve_info.items():
                # Sanitize HTML content
                if isinstance(value, dict):
                    value = json.dumps(value)  # Convert dictionary to string
                value = bleach.clean(str(value), tags=[], strip=True)  # Ensure only text is added
                paragraph_text = f"<b>{key.capitalize()}:</b> {value}\n\n"
                content.append(Paragraph(paragraph_text, normal_style))

            # If CVSS score is available, add it to the content
            if 'cvss' in cve_info:
                cvss_score = cve_info['cvss']
                paragraph_text = f"<b>CVSS Score:</b> {cvss_score}\n\n"
                content.append(Paragraph(paragraph_text, normal_style))

            # Build content and add to PDF
            doc.build(content)

            print(f"PDF generated successfully: {cve_id}.pdf")
        except Exception as e:
            print(f"Error generating PDF: {e}")
    else:
        print("CVE information not found or error fetching data.")

# Function to generate the report and open references
def generate_report_and_open_references(cve_id):
    # Fetch CVE information
    cve_info = fetch_cve_info(cve_id)
    
    # Generate PDF report
    generate_pdf(cve_info, cve_id)
    
    # Open reference sites
    open_references(cve_id)

# Main function
def main():
    while True:
        print("[1]: Continue")
        print("[2]: Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            cve_id = input("Enter CVE ID: ").strip()
            cve_regex = r'^CVE-\d{4}-\d{4,}$'
            if re.match(cve_regex, cve_id):
                # Check if the CVE exists
                generate_report_and_open_references(cve_id)
            else:
                print("Please enter a valid CVE ID (e.g., CVE-2017-0144)")
        elif choice == "2":
            break
        else:
            print("Invalid input. Please enter a valid choice (1 or 2).")

    driver.quit()

if __name__ == "__main__":
    main()