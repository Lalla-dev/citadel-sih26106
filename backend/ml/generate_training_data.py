"""
Citadel Security Platform - ML Training Data Generator
Generates a curated synthetic training corpus for the TF-IDF + Logistic Regression
phishing/BEC classifier. Each sample is labeled as 'benign', 'phishing', or 'bec'.
"""
import random
import json
from pathlib import Path

# Benign email templates
BENIGN_TEMPLATES = [
    "Hi team, please review the attached quarterly report and provide feedback by Friday.",
    "Meeting reminder: Sprint planning is scheduled for tomorrow at 10 AM in the main conference room.",
    "The project deadline has been extended to next week. Please update your tasks accordingly.",
    "Hello, I wanted to follow up on our conversation regarding the new feature implementation.",
    "Please find the updated design specifications in the shared drive under Project Alpha folder.",
    "Team lunch is this Thursday at noon. Please RSVP by end of day Tuesday.",
    "The server maintenance window is scheduled for Saturday 2 AM to 6 AM. No action required.",
    "Congratulations on completing the milestone! Great work everyone.",
    "FYI - The office will be closed on Monday for the national holiday.",
    "Hi, could you send me the latest version of the architecture diagram?",
    "The training session on cloud security best practices will be held next Wednesday.",
    "Please submit your timesheet by end of day Friday.",
    "The code review for the authentication module is pending. Please take a look when you have time.",
    "Welcome aboard! Your onboarding documents are attached. Please complete them by your first day.",
    "The IT department will be upgrading the VPN client next week. Instructions will follow.",
    "Reminder: Annual performance reviews are due by the end of this month.",
    "The new parking policy takes effect starting next Monday. Details in the attached memo.",
    "Hi, I've updated the project wiki with the latest API documentation.",
    "The bug fix for issue #4521 has been deployed to the staging environment for testing.",
    "Good morning, the daily standup will be at 9:15 AM today instead of the usual 9:30.",
    "Please review and approve the purchase order for the new development servers.",
    "The team building event is scheduled for next Friday afternoon. Activities include bowling.",
    "Reminder: Complete the mandatory cybersecurity awareness training by end of quarter.",
    "The database migration script has been tested successfully. Ready for production deployment.",
    "Hi all, the weekly status report is attached. Key highlights are on page 2.",
    "Your request for additional cloud compute resources has been approved.",
    "The new hire orientation schedule for October has been posted on the intranet.",
    "Please update your emergency contact information in the HR portal.",
    "The software license renewal for our development tools is due next month.",
    "FYI: The company holiday party will be on December 15th this year.",
    "Good afternoon, I wanted to share the latest customer satisfaction survey results.",
    "The release candidate for version 3.2 is ready for QA testing.",
    "Please ensure all documentation is updated before the audit next week.",
    "The network team has resolved the connectivity issues reported yesterday.",
    "Hi, can we schedule a 30 minute call to discuss the integration requirements?",
    "The monthly all-hands meeting will be streamed live at 2 PM Eastern.",
    "Your PTO request for the last week of December has been approved.",
    "The CI/CD pipeline improvements reduced build time by 40%. Great job team!",
    "Please review the attached contract amendment and provide your comments.",
    "The office supply order has been placed. Expected delivery is Thursday.",
    "Reminder to update your direct deposit information if you recently changed banks.",
    "The product roadmap presentation is scheduled for Tuesday morning.",
    "Hi team, the retrospective action items from last sprint are in the shared doc.",
    "The disaster recovery drill will take place next Saturday. Participation is mandatory.",
    "Please submit your expense reports for Q3 by October 15th.",
    "The new employee handbook has been published. Please acknowledge receipt.",
    "Hi, the design review meeting has been moved to 3 PM to accommodate all timezones.",
    "The penetration test report for our web application has been shared with the security team.",
    "The cafeteria menu for next week has been posted on the bulletin board.",
    "Reminder: The company health fair is this Wednesday in the main lobby.",
]

# Phishing email templates
PHISHING_TEMPLATES = [
    "Your account has been compromised. Click here immediately to verify your identity and secure your account.",
    "URGENT: Unusual sign-in activity detected on your account. Verify now to prevent suspension.",
    "Your password will expire in 24 hours. Click the link below to update your credentials immediately.",
    "Security Alert: We detected unauthorized access to your account from an unknown device. Verify now.",
    "Your email storage is full. Click here to upgrade your storage or risk losing incoming messages.",
    "ACTION REQUIRED: Your account will be suspended unless you confirm your identity within 12 hours.",
    "Dear user, your recent transaction of $4,299 has been flagged. Click to dispute if unauthorized.",
    "Your package delivery failed. Update your shipping address immediately to receive your package.",
    "Congratulations! You have been selected for a special reward. Claim your prize by clicking below.",
    "Your subscription has expired. Renew now to avoid losing access to all your documents and files.",
    "NOTICE: Your tax refund of $3,847 is ready for processing. Submit your bank details to receive payment.",
    "Your account login was blocked due to suspicious activity. Re-authenticate to restore access.",
    "Important: Microsoft Office 365 requires immediate re-verification of your credentials.",
    "Alert: Your credit card ending in 4521 has been charged $789. Click here if you did not authorize this.",
    "Final warning: Your account will be permanently deleted in 48 hours unless you verify your identity.",
    "Dear customer, your online banking session has expired. Log in again to continue using services.",
    "Security notification: Someone tried to reset your password. If this was not you, click here immediately.",
    "Your Apple ID has been locked for security reasons. Click here to unlock and verify your account.",
    "URGENT: Your company email will be deactivated. Complete the verification form to maintain access.",
    "Your antivirus subscription has expired leaving your device vulnerable. Renew immediately.",
    "Warning: Unusual activity detected on your PayPal account. Verify your identity to avoid restrictions.",
    "IT Department: System upgrade requires all employees to re-enter their login credentials.",
    "Your Netflix account has been suspended due to a billing issue. Update your payment method now.",
    "ALERT: Your social security number has been found on the dark web. Click to protect your identity.",
    "Dear valued customer, please confirm your account details to avoid service interruption.",
    "Your Amazon order #112-4879362 cannot be delivered. Update your address to receive your items.",
    "Immediate action needed: Your webmail quota has been exceeded. Verify to increase storage.",
    "Security update required: Re-enter your credentials to maintain access to the corporate portal.",
    "Your bank has detected fraudulent charges on your account. Click to review and secure your finances.",
    "IMPORTANT: Your LinkedIn account will be restricted. Complete verification to keep your profile active.",
    "System administrator notice: All users must reset their passwords by clicking the secure link below.",
    "Your Google Drive storage is 99% full. Upgrade now or files will be automatically deleted.",
    "Warning: Your domain registration is about to expire. Renew immediately to keep your website online.",
    "Unauthorized login attempt from Russia detected on your account. Secure your account now.",
    "Your insurance claim has been approved. Submit your personal details to receive the payout.",
    "NOTICE: Your voicemail message is pending. Click here to listen to your new voicemail.",
    "Your account verification is incomplete. Submit the required documents to avoid account closure.",
    "IT Security: Mandatory security patch requires you to download and install the attached update.",
    "Your flight reservation has been changed. Click to view the updated itinerary and confirm.",
    "Dear employee, HR requires you to update your personal information through the secure portal below.",
]

# BEC email templates
BEC_TEMPLATES = [
    "I need you to process a wire transfer of $125,000 to the following account immediately. This is strictly confidential.",
    "Can you handle a payment for me? I need $95,000 wired to our new vendor. I'll share the bank details.",
    "This is urgent. I need you to purchase $5,000 in gift cards for client appreciation. Keep this between us.",
    "Please update the vendor payment account for our supplier. Their new routing number and account details are below.",
    "I am in a meeting with the board and cannot take calls. Process the attached invoice payment immediately.",
    "We are completing a confidential acquisition. Wire $250,000 to the escrow account. Do not discuss with anyone.",
    "Change the direct deposit account for my payroll immediately. New bank details: routing 021000089 account 738291046.",
    "Urgent: Our vendor has changed their banking details. Update the ACH payment to the new account before the deadline.",
    "I need you to make a payment of $78,500 to the law firm handling our merger. Time sensitive, handle today.",
    "Please buy 20 Amazon gift cards at $200 each and send me the codes. This is for employee rewards.",
    "Our overseas partner requires immediate payment. Wire $190,000 to their international account. SWIFT code attached.",
    "I am authorizing a funds transfer of $340,000 for the real estate closing. Process by end of business today.",
    "Do not discuss this with anyone else. I need $45,000 transferred to the following beneficiary account today.",
    "Process the attached invoice from our legal team. Payment of $67,000 is due immediately via wire transfer.",
    "Please update our vendor master file with the new banking instructions I am forwarding. This is effective immediately.",
    "I need your help with a time-sensitive matter. Can you process a payment of $155,000 before the bank closes?",
    "Strictly confidential: Purchase 30 iTunes gift cards at $100 each. Scratch off the backs and email me photos of the codes.",
    "Our bank account details have changed due to the corporate restructuring. Update all pending payments to the new account.",
    "Handle this personally. I need $88,000 wired to the following account for a settlement payment. Do not delay.",
    "This is the CEO. I am traveling and need you to handle a payment urgently. Reply to this email only.",
    "Please process payroll early this month. Additionally, change my direct deposit to the new account ending in 7834.",
    "We need to pay a retainer fee of $200,000 to our new consulting firm. Wire the amount today.",
    "Urgent request: I need you to divert the payment for invoice INV-2026-1847 to our updated remittance account.",
    "I am in a board meeting all day. Please handle the attached wire transfer request without disturbing me.",
    "Our attorney requires an immediate payment of $175,000 for the pending litigation settlement.",
    "Confidential: Change the payment instructions for ABC Corp to the new bank account effective immediately.",
    "I need $35,000 in Google Play gift cards for a surprise employee appreciation event. Purchase today.",
    "Process the funds transfer of $420,000 for the equipment lease. Details in the attached document.",
    "Please update the remittance instructions for all payments to Global Shipping LLC. New SWIFT and account below.",
    "Do not call me. I am handling a sensitive matter. Wire $92,000 to the account I will provide shortly.",
]

def generate_variations(template: str, n: int = 3) -> list:
    """Generate slight variations of a template for training diversity."""
    variations = [template]
    
    greetings = ["", "Hi, ", "Hello, ", "Dear colleague, ", "Good morning, ", "Good afternoon, "]
    signoffs = ["", "\nBest regards", "\nThanks", "\nRegards", "\nSincerely", "\nThank you"]
    
    for _ in range(n - 1):
        greeting = random.choice(greetings)
        signoff = random.choice(signoffs)
        var = greeting + template + signoff
        variations.append(var)
    
    return variations

def generate_training_data(output_path: str):
    """
    Generates the full training corpus as JSONL with fields: text, label.
    Labels: 0=benign, 1=phishing, 2=bec
    """
    samples = []
    
    for template in BENIGN_TEMPLATES:
        for var in generate_variations(template, n=4):
            samples.append({"text": var, "label": 0})
    
    for template in PHISHING_TEMPLATES:
        for var in generate_variations(template, n=4):
            samples.append({"text": var, "label": 1})
    
    for template in BEC_TEMPLATES:
        for var in generate_variations(template, n=4):
            samples.append({"text": var, "label": 2})
    
    random.seed(42)
    random.shuffle(samples)
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, "w", encoding="utf-8") as f:
        for sample in samples:
            f.write(json.dumps(sample) + "\n")
    
    label_counts = {0: 0, 1: 0, 2: 0}
    for s in samples:
        label_counts[s["label"]] += 1
    
    print(f"Generated {len(samples)} training samples -> {output_path}")
    print(f"  Benign: {label_counts[0]}, Phishing: {label_counts[1]}, BEC: {label_counts[2]}")
    return len(samples)

if __name__ == "__main__":
    generate_training_data("backend/ml/training_data.jsonl")
