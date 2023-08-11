import base64

from django.core.mail import EmailMultiAlternatives, get_connection, send_mail
from django.template.loader import render_to_string
# from account.conf import settings
from blood_donation import settings
from django.conf import settings


def forgot_password_email(self, ctx):
    subject = render_to_string("subject/forgot_password.txt", ctx)
    subject = "".join(subject.splitlines())
    message = render_to_string("email/forgot_password.html", ctx)
    msg = EmailMultiAlternatives(subject, 'message', settings.DEFAULT_FROM_EMAIL, [ctx['email']])
    msg.attach_alternative(message, "text/html")
    send_mail(msg)


class AccountDefaultHookSet(object):

    # def registration_email(self, ctx):
    #     subject = render_to_string("subject/registration_success.txt", ctx)
    #     subject = "".join(subject.splitlines())
    #     message = render_to_string("email/registration_success.html", ctx)
    #     msg = EmailMultiAlternatives(subject, 'message', settings.DEFAULT_FROM_EMAIL, [ctx['email']])
    #     msg.attach_alternative(message, "text/html")
    #     msg.send()

    # def referral_invitation_email(self, ctx):
    #     subject = render_to_string("subject/referral_invite.txt", ctx)
    #     subject = "".join(subject.splitlines())
    #     message = render_to_string("email/referral_invite.html", ctx)
    #     msg = EmailMultiAlternatives(subject, 'message', settings.DEFAULT_FROM_EMAIL, [ctx['email']])
    #     msg.attach_alternative(message, "text/html")
    #     msg.send()

    def forgot_password_email(self, ctx):
        subject = render_to_string("subject/forgot_password.txt", ctx)
        subject = "".join(subject.splitlines())
        message = "Dummy"
        html_content = render_to_string("email/forgot_password.html", ctx)
        msg = EmailMultiAlternatives(subject, 'message', settings.DEFAULT_FROM_EMAIL, [ctx['email']])
        msg.attach_alternative(message, "text/html")
        # send_mail(msg)
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[ctx['email']],
            html_message=html_content)
        # msg.send()

    # def guardian_invitation_email(self, ctx):
    #     subject = render_to_string("subject/guardian_invitation.txt", ctx)
    #     subject = "".join(subject.splitlines())
    #     message = render_to_string("email/guardian_invitation.html", ctx)
    #     msg = EmailMultiAlternatives(subject, 'message', settings.DEFAULT_FROM_EMAIL, [ctx['email']])
    #     msg.attach_alternative(message, "text/html")
    #     msg.send()

    # def change_email(self, ctx):
    #     subject = render_to_string("subject/change_email.txt", ctx)
    #     subject = "".join(subject.splitlines())
    #     message = "Dummy"
    #     html_content = render_to_string("email/change_email.html", ctx)
    #     msg = EmailMultiAlternatives(subject, 'message', settings.DEFAULT_FROM_EMAIL, [ctx['email']])
    #     msg.attach_alternative(message, "text/html")
    #     # send_mail(msg)
    #     send_mail(
    #         subject=subject,
    #         message=message,
    #         from_email=settings.DEFAULT_FROM_EMAIL,
    #         recipient_list=[ctx['email']],
    #         html_message=html_content)
    #
    # def change_number(self, ctx):
    #     subject = render_to_string("subject/change_number.txt", ctx)
    #     subject = "".join(subject.splitlines())
    #     message = render_to_string("email/change_number.html", ctx)
    #     msg = EmailMultiAlternatives(subject, 'message', settings.DEFAULT_FROM_EMAIL, [ctx['email']])
    #     msg.attach_alternative(message, "text/html")
    #     msg.send()
    #
    # def death_confirmation_email(self, ctx):
    #     subject = render_to_string("subject/death_confirmation.txt", ctx)
    #     subject = "".join(subject.splitlines())
    #     message = render_to_string("email/death_confirmation.html", ctx)
    #     msg = EmailMultiAlternatives(subject, 'message', settings.DEFAULT_FROM_EMAIL, [ctx['email']])
    #     msg.attach_alternative(message, "text/html")
    #     msg.send()


class HookProxy(object):

    def __getattr__(self, attr):
        return getattr(settings.ACCOUNT_HOOKSET, attr)


hook_set = HookProxy()
