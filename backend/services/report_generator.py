from fpdf import FPDF
import datetime

class PhishingReport(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 15)
        self.cell(0, 10, 'ThreatEye AI Phishing & Security Report', border=False, align='C')
        self.ln(5)
        self.set_font('helvetica', 'I', 10)
        self.cell(0, 10, f'Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', align='R')
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', align='C')

def generate_analytics_pdf(general_stats: dict, campaign_results: list) -> bytearray:
    """
    Generates a PDF report containing general stats and campaign results (including victims).
    """
    pdf = PhishingReport()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Summary Section
    pdf.set_font('helvetica', 'B', 12)
    pdf.set_text_color(0, 50, 150)
    pdf.cell(0, 10, "1. EXECUTIVE SUMMARY", ln=True)
    pdf.set_text_color(0,0,0)
    pdf.set_font('helvetica', '', 10)
    
    pdf.cell(0, 7, f"Total Emails Monitored: {general_stats.get('total_emails_scanned', 0)}", ln=True)
    pdf.cell(0, 7, f"Detected Threats: {general_stats.get('suspicious_emails', 0)}", ln=True)
    pdf.cell(0, 7, f"Quarantined Items: {general_stats.get('quarantined_emails', 0)}", ln=True)
    pdf.ln(5)
    
    # Simulation Results Section
    pdf.set_font('helvetica', 'B', 12)
    pdf.set_text_color(200, 0, 50)
    pdf.cell(0, 10, "2. PHISHING SIMULATION RESULTS & VICTIM LIST", ln=True)
    pdf.set_text_color(0,0,0)
    pdf.set_font('helvetica', '', 10)
    
    if not campaign_results:
        pdf.cell(0, 7, "No simulation data available.", ln=True)
    else:
        for idx, camp in enumerate(campaign_results):
            pdf.set_font('helvetica', 'B', 10)
            pdf.ln(2)
            pdf.cell(0, 7, f"Campaign {idx+1}: {camp.get('name', 'N/A')} ({camp.get('launch_date', 'Unknown')})", ln=True)
            pdf.set_font('helvetica', '', 10)
            
            # Show stats for this campaign
            results = camp.get('results', {})
            total = results.get('total', 0)
            clicked = results.get('clicked', 0)
            click_rate = round((clicked / total) * 100, 1) if total > 0 else 0
            
            pdf.cell(0, 6, f"   Status: {camp.get('status', 'N/A')}", ln=True)
            pdf.cell(0, 6, f"   Total Targets: {total}", ln=True)
            pdf.cell(0, 6, f"   Caught (Clicked/Submitted): {clicked} ({click_rate}% Failure Rate)", ln=True)
            
            # Victim List
            victims = camp.get('victims', [])
            if victims:
                pdf.set_font('helvetica', 'BI', 9)
                pdf.cell(0, 6, "   Caught Users List:", ln=True)
                pdf.set_font('helvetica', '', 9)
                for victim in victims:
                    pdf.cell(0, 5, f"     - {victim.get('email')} ({victim.get('first_name', '')} {victim.get('last_name', '')})", ln=True)
            else:
                pdf.cell(0, 6, "   No users fell for this campaign.", ln=True)
            
            pdf.ln(3)
            if pdf.get_y() > 250: # Avoid page break issues
                pdf.add_page()

    return bytes(pdf.output())
