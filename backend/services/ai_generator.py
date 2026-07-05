import os
from dotenv import load_dotenv
from framework.model_provider import get_llm_client, get_model_name

load_dotenv()

def generate_phishing_email(target_name: str, department: str, company: str, context: str = "") -> dict:
    """
    Generates a targeted phishing email using an LLM based on OSINT/Target data.
    """
    prompt = f"""
    You are a professional red teamer simulating a sophisticated phishing attack.
    Create a highly personalized, convincing phishing email for the following target:
    
    Name: {target_name}
    Department: {department}
    Company: {company}
    Additional Context: {context}

    The email should have a sense of urgency but remain professional. It should encourage the user to click a link.
    Return ONLY a JSON object with the following keys:
    "subject": The email subject line.
    "body_text": The plain text version of the email. Use {{.URL}} as the placeholder for the phishing link.
    "body_html": The HTML version of the email. Use {{.URL}} as the placeholder for the phishing link.
    """

    try:
        client = get_llm_client()  # resolved fresh from settings
        response = client.chat.completions.create(
            model=get_model_name(),
            messages=[{"role": "user", "content": prompt}],
            response_format={ "type": "json_object" }
        )
        import json
        result = json.loads(response.choices[0].message.content)
        return result
    except Exception as e:
        print(f"Error generating email: {e}")
        # Fallback template
        return {
            "subject": f"Urgent Action Required: {company} Account Update",
            "body_text": f"Hi {target_name},\n\nPlease update your {company} ({department}) credentials here: {{.URL}}\n\nThanks.",
            "body_html": f"<p>Hi {target_name},</p><p>Please update your {company} ({department}) credentials <a href='{{.URL}}'>here</a>.</p><p>Thanks.</p>"
        }
