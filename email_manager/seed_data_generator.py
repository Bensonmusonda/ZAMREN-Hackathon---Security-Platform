import uuid
from datetime import datetime, timezone
import httpx
import asyncio

# Ensure you have httpx installed: pip install httpx

seed_emails = [
    {
        "email_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sender": "noreply@legitcorp.com",
        "recipients": ["admin@bennieslab.com"],
        "subject": "Important: Your Account Security Update",
        "body": "Dear valued customer,\n\nWe detected unusual activity on your account. Please click the link below to verify your identity and secure your account immediately.\n\nhttps://security-update.com/verify\n\nSincerely,\nLegitCorp Security Team"
    },
    {
        "email_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sender": "marketing@onlineoffers.xyz",
        "recipients": ["admin@bennieslab.com", "user@bennieslab.com"],
        "subject": "🎉 Claim Your FREE Gift Card Now! Limited Time Offer!",
        "body": "Congratulations! You have been selected to receive a FREE $500 gift card! Don't miss out on this incredible opportunity.\n\nClick here to claim your prize: http://exclusive-offer.xyz/freegift\n\nThis offer expires in 24 hours. Act fast!\n\nUnsubscribe: http://onlineoffers.xyz/unsubscribe"
    },
    {
        "email_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sender": "info@projectupdates.org",
        "recipients": ["user@bennieslab.com"],
        "subject": "Weekly Project Sync - Meeting Notes Attached",
        "body": "Hi Team,\n\nPlease find attached the meeting notes from our weekly project synchronization call. We discussed progress on Module A and planned next steps for Module B.\n\nKey takeaways:\n- Module A: On track for completion by end of next week.\n- Module B: Requirements finalized, development to start Monday.\n\nLet me know if you have any questions or require further clarification.\n\nBest regards,\nProject Manager"
    },
    {
        "email_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sender": "support@bankofafrica.com",
        "recipients": ["admin@bennieslab.com"],
        "subject": "Urgent: Your Bank Account Has Been Suspended",
        "body": "Dear Customer,\n\nYour Bank of Africa account has been temporarily suspended due to suspicious login attempts from an unrecognized device.\n\nTo reactivate your account and avoid further restrictions, please verify your details by visiting:\n\nhttps://bankofafrica-verify.net/login_secure\n\nFailure to do so will result in permanent account closure.\n\nThank you for your cooperation,\nBank of Africa Security Team"
    },
    {
        "email_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sender": "newsletter@techinsights.com",
        "recipients": ["user@bennieslab.com", "another.user@example.com"],
        "subject": "Your Daily Tech News Digest - AI Breakthroughs & Cybersecurity Trends",
        "body": "Good morning,\n\nHere's your daily dose of tech news:\n\n1. AI Breakthrough: New algorithm achieves human-level performance in complex reasoning tasks.\n2. Cybersecurity Trends: Ransomware attacks on the rise, best practices for prevention.\n3. Gadget Review: Latest smartphone review - worth the upgrade?\n\nRead more at [Link to TechInsights Blog]\n\nBest,\nTechInsights Team"
    },
    {
        "email_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sender": "hr@mycompany.com",
        "recipients": ["admin@bennieslab.com"],
        "subject": "Payslip for June 2025 - Action Required",
        "body": "Dear Employee,\n\nYour payslip for June 2025 is now available. Due to a system upgrade, you need to log in to the new HR portal to view and download it.\n\nClick here: https://new-hrportal.mycompany.com/login\n\nPlease complete this by end of day Friday.\n\nRegards,\nHR Department"
    }
]

async def send_email_to_email_manager(email_data):
    """
    Sends an email to the Email Manager's /ingest-email endpoint.
    Assumes Email Manager is running on http://localhost:5000.
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post("http://localhost:5000/ingest-email", json=email_data)
            response.raise_for_status() # Raise an exception for bad status codes
            print(f"Email '{email_data['subject']}' sent to Email Manager. Status: {response.status_code}, Response: {response.json()}")
    except httpx.RequestError as e:
        print(f"❌ Network error sending email '{email_data['subject']}' to Email Manager: {e}")
    except httpx.HTTPStatusError as e:
        print(f"❌ HTTP error sending email '{email_data['subject']}' to Email Manager: {e.response.status_code} - {e.response.text}")
    except Exception as e:
        print(f"❌ An unexpected error occurred while sending email '{email_data['subject']}': {e}")

async def main():
    """
    Iterates through the seed emails and sends each one to the Email Manager.
    """
    print("Starting to send seed emails to Email Manager...")
    for email in seed_emails:
        await send_email_to_email_manager(email)
    print("Finished sending seed emails.")

if __name__ == "__main__":
    # Run the main asynchronous function
    asyncio.run(main())