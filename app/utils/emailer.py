from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from ..config import settings

def send_email(to_email: str, subject: str, html_body: str):
    message = Mail(
        from_email=settings.FROM_EMAIL,     # Endereço remetente verificado
        to_emails=to_email,
        subject=subject,
        html_content=html_body
    )
    sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
    response = sg.send(message)
    if response.status_code >= 400:
        raise Exception(f"SendGrid send failed with status {response.status_code}")
