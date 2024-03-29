import requests
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import bleach
import json
import webbrowser

def fetch_cve_info(cve_id):
    api_url = f"https://cve.circl.lu/api/cve/{cve_id}"
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

def generate_pdf(cve_info, cve_id): #second generator to open a browser
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

            # Open the CVE details page in a web browser
            cve_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            webbrowser.open(cve_url)

            print(f"PDF generated successfully: {cve_id}.pdf")
        except Exception as e:
            print(f"Error generating PDF: {e}")
    else:
        print("CVE information not found or error fetching data.")


def main():
    cve_id = input("Enter CVE ID (e.g., CVE-2021-3456): ")
    cve_info = fetch_cve_info(cve_id)
    generate_pdf(cve_info, cve_id)

if __name__ == "__main__":
    main()
