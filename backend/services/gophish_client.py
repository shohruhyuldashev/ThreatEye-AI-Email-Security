import os
from gophish import Gophish
from gophish.models import *
from dotenv import load_dotenv
from db import get_db_connection

load_dotenv()

def get_api():
    """Dynamically initializes and returns the GoPhish API client using settings from the DB."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT key, value FROM settings WHERE key IN ('sim_gophish_url', 'sim_gophish_api_key', 'gophish_url', 'gophish_key')")
    settings = dict(c.fetchall())
    conn.close()

    # Try both prefixed and non-prefixed keys for compatibility
    gophish_url = settings.get('sim_gophish_url') or settings.get('gophish_url') or os.getenv("GOPHISH_URL", "http://gophish:3333")
    gophish_api_key = settings.get('sim_gophish_api_key') or settings.get('gophish_key') or os.getenv("GOPHISH_API_KEY", "")

    if not gophish_api_key:
        return None
        
    # Clean the URL - GoPhish SDK expects the base URL without trailing /api/
    gophish_url = gophish_url.strip()
    if gophish_url.endswith('/api/'):
        gophish_url = gophish_url[:-5]
    if gophish_url.endswith('/api'):
        gophish_url = gophish_url[:-4]
    if gophish_url.endswith('/'):
        gophish_url = gophish_url[:-1]
        
    try:
        api = Gophish(gophish_api_key, host=gophish_url, verify=False)
        return api
    except Exception as e:
        print(f"Failed to initialize GoPhish client: {e}")
        return None

# For backward compatibility / quick imports in other parts if they rely on a global api. 
# However, functions inside here should call get_api() to ensure they get fresh keys
api = get_api()

def create_campaign_with_generated_email(target_info: dict, generated_email: dict):
    client = get_api()
    if not client:
        return {"error": "GoPhish API not configured or unreachable"}
        
    try:
        # 1. Create User Group
        group = Group(name=f"Group_{target_info['name']}_{os.urandom(4).hex()}")
        group.targets = [User(first_name=target_info['name'], email=target_info['email'])]
        group = client.groups.post(group)

        # 2. Create Template
        template = Template(
            name=f"Template_{target_info['name']}_{os.urandom(4).hex()}",
            subject=generated_email.get('subject', 'Important Notice'),
            text=generated_email.get('body_text', ''),
            html=generated_email.get('body_html', '')
        )
        template = client.templates.post(template)

        # 3. Create Campaign
        # Note: We need a sender profile, landing page etc.
        # Assuming defaults or creating dummy ones for proof of concept
        # In a real tool, these would be configured or passed in.
        
        # We will stop here for the basic implementation 
        # as getting existing SMTP profiles is needed for a full launch
        
        return {
            "status": "success",
            "group_id": group.id,
            "template_id": template.id,
            "message": "Template and Group created in GoPhish"
        }
    except Exception as e:
        return {"error": str(e)}

def get_campaign_stats(campaign_id: int):
    client = get_api()
    if not client: return None
    try:
        campaign = client.campaigns.get(campaign_id=campaign_id)
        return campaign.results
    except Exception:
        return None

def trigger_random_campaign():
    """
    Used by the background scheduler to randomly test employees with AI-generated emails.
    """
    client = get_api()
    print("Triggering random scheduled Phishing Campaign...")
    if not client:
        print("GoPhish API not configured. Cannot trigger automated campaign.")
        return
        
    # In a full production environment, this would pull a random employee from a DB/AD
    # For now, we simulate pulling random target data
    dummy_target = {
        "name": "Employee User",
        "email": "employee@example.com",
        "department": "IT",
        "company": "Company Corp"
    }
    
    from services.ai_generator import generate_phishing_email
    email_data = generate_phishing_email(
        target_name=dummy_target["name"],
        department=dummy_target["department"],
        company=dummy_target["company"]
    )
    
    result = create_campaign_with_generated_email(target_info=dummy_target, generated_email=email_data)
    print(f"Random campaign trigger result: {result}")
