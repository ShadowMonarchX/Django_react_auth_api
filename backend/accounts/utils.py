from django.core.mail import EmailMessage
from django.conf import settings
from datetime import datetime, timedelta
from django.utils.crypto import get_random_string

def send_generated_otp_to_email(email, request):
    try:
        subject = "One-Time Passcode for Email Verification"
        otp = get_random_string(6, allowed_chars='0123456789')  
        email_body = f"Hi {email}, your OTP for email verification is: {otp}"

        request.session['otp'] = otp
        request.session['otp_email'] = email
        request.session['otp_expiry'] = (datetime.now() + timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S")

        # print("Session data set:")
        # print("OTP:", request.session.get('otp'))
        # print("Email:", request.session.get('otp_email'))
        # print("Expiry:", request.session.get('otp_expiry'))

        request.session.modified = True
        request.session.save()

        email_msg = EmailMessage(subject=subject, body=email_body, from_email=settings.EMAIL_HOST_USER, to=[email])
        email_msg.send()

        return True
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return False


def send_normal_email(data):
    email=EmailMessage(
        subject=data['email_subject'],
        body=data['email_body'],
        from_email=settings.EMAIL_HOST_USER,
        to=[data['to_email']]
    )
    email.send()


