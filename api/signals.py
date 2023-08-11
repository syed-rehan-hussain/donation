# signals.py

from django.dispatch import Signal

# Custom signal for sending an email
send_email_signal = Signal()
