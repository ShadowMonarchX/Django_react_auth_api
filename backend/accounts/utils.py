import logging
from django.core.mail import EmailMessage
import random
from django.conf import settings
from .models import User, OneTimePassword
from django.contrib.sites.shortcuts import get_current_site

logger = logging.getLogger(__name__)

def send_generated_otp_to_email(email, request):
    try:
        subject = "One time passcode for Email verification"
        otp = random.randint(100000, 999999)  
        current_site = get_current_site(request).domain  
        user = User.objects.get(email=email) 
        email_body = f"Hi {user.email}, thanks for signing up on {current_site}. Please verify your email with the one-time passcode: {otp}"
        

        existing_otp = OneTimePassword.objects.filter(user=user).first()
        
        if existing_otp:
            existing_otp.otp = otp
            existing_otp.save()
        else:

            otp_obj = OneTimePassword.objects.create(user=user, otp=otp)

        from_email = settings.EMAIL_HOST_USER
        d_email = EmailMessage(subject=subject, body=email_body, from_email=from_email, to=[user.email])
        email_sent = d_email.send() 
        
        if email_sent == 1:  
            logger.info(f"OTP sent to {email} successfully.")
        else:
            logger.warning(f"Failed to send OTP to {email}.")
        
    except User.DoesNotExist:
        logger.error(f"User with email {email} does not exist.")
    except Exception as e:
        logger.error(f"Error sending OTP to {email}: {str(e)}")
        raise


def send_normal_email(data):
    email=EmailMessage(
        subject=data['email_subject'],
        body=data['email_body'],
        from_email=settings.EMAIL_HOST_USER,
        to=[data['to_email']]
    )
    email.send()