import random
import smtplib
from email.message import EmailMessage

def generate_code():
    return str(random.randint(100000, 999999))

def send_verification_code(email, code):
    msg = EmailMessage()
    msg['Subject'] = 'Your AspireMatch Verification Code'
    msg['From'] = 'AspireMatch <hertzkin@gmail.com>'
    msg['To'] = email
    msg.set_content(f'''
Your verification code is:

{code}

This code will expire in 5 minutes.
If you did not request this, ignore this email.
''')

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login('hertzkin@gmail.com', 'jvyc dzlf ihvf moqo')
        server.send_message(msg)
