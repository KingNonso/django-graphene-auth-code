import time
import string

from django.conf import settings as django_settings
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.db import models, transaction
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.crypto import get_random_string

from .constants import TokenAction
from .exceptions import EmailAlreadyInUseError, UserAlreadyVerifiedError, WrongUsageError, TokenScopeError
from .settings import graphql_auth_settings as app_settings
from .signals import user_verified
from .utils import get_token, get_token_payload

UserModel = get_user_model()


class OTPCode(models.Model):
    """
    Model to store the One Time Pass verification code that is sent to the email.
    """
    user = models.ForeignKey(
        django_settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="otp"
    )
    email = models.EmailField(
        "email",
        max_length=255,
        blank=False,
        null=False,
        help_text="The email to which the code was sent.",
    )
    code = models.CharField(max_length=6)
    used = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.code

    class Meta:
        verbose_name = "verification code"
        verbose_name_plural = "verification codes"
        ordering = ["-created"]

    def generate_numeric_code(self, length=6):
        """
        Generate a random 6 digit string of numbers.
        We use this formatting to allow leading 0s.
        """
        otp = get_random_string(length, allowed_chars=string.digits)
        # Check if the code already exists in the database
        if OTPCode.objects.filter(code=otp).exists():
            # Entity with the same code attribute exists, so generate a new one
            self.generate_numeric_code(length)
        return otp
    
    def save(self, *args, **kwargs):
        """
        Override the save method to generate a numeric code.
        """
        length = 6
        if not self.code:
            self.code = self.generate_numeric_code(length)
        # Check if the email already exists in the database
        if self.pk is None and OTPCode.objects.filter(email=self.email).exists():
            # Entity with the same attributes exists, hence mark them all as used
            OTPCode.objects.filter(email=self.email).update(used=True)
            
        super().save(*args, **kwargs)
    
    @classmethod
    def get_token_code(cls, user):
        token = OTPCode.objects.create(user=user, email=user.email)
        return token

    @classmethod
    def verify_token_code(cls, email, token, timestamp):
        token = OTPCode.objects.filter(email=email, code=token, used=False)
        if token.exists():
            # Todo: commute datetime comparison to check if token has expired
            return token.first()
        raise TokenScopeError    
        


class UserStatus(models.Model):
    """
    A helper model that handles user account stuff.
    """

    user = models.OneToOneField(django_settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="status")
    verified = models.BooleanField(default=False)
    archived = models.BooleanField(default=False)
    secondary_email = models.EmailField(blank=True, null=True)

    def __str__(self):
        return "%s - status" % (self.user)

    def send(self, subject, template, context, recipient_list=None):
        _subject = render_to_string(subject, context).replace("\n", " ").strip()
        html_message = render_to_string(template, context)
        message = strip_tags(html_message)

        return send_mail(
            subject=_subject,
            from_email=app_settings.EMAIL_FROM,
            message=message,
            html_message=html_message,
            recipient_list=(recipient_list or [getattr(self.user, UserModel.EMAIL_FIELD)]),  # type: ignore
            fail_silently=False,
        )

    def get_email_context(self, info, path, action, **kwargs):
        # token = get_token(self.user, action, **kwargs)
        token = OTPCode.get_token_code(self.user)
        site = get_current_site(info.context)
        return {
            "user": self.user,
            "request": info.context,
            "token": token,
            "port": info.context.get_port(),
            "site_name": site.name,
            "domain": site.domain,
            "protocol": "https" if info.context.is_secure() else "http",
            "path": path,
            "timestamp": time.time(),
            **app_settings.EMAIL_TEMPLATE_VARIABLES,
        }

    def send_activation_email(self, info, *args, **kwargs):
        email_context = self.get_email_context(info, app_settings.ACTIVATION_PATH_ON_EMAIL, TokenAction.ACTIVATION)
        template = app_settings.EMAIL_TEMPLATE_ACTIVATION
        subject = app_settings.EMAIL_SUBJECT_ACTIVATION
        return self.send(subject, template, email_context, *args, **kwargs)

    def resend_activation_email(self, info, *args, **kwargs):
        if self.verified is True:
            raise UserAlreadyVerifiedError
        email_context = self.get_email_context(info, app_settings.ACTIVATION_PATH_ON_EMAIL, TokenAction.ACTIVATION)
        template = app_settings.EMAIL_TEMPLATE_ACTIVATION_RESEND
        subject = app_settings.EMAIL_SUBJECT_ACTIVATION_RESEND
        return self.send(subject, template, email_context, *args, **kwargs)

    def send_password_set_email(self, info, *args, **kwargs):
        email_context = self.get_email_context(info, app_settings.PASSWORD_SET_PATH_ON_EMAIL, TokenAction.PASSWORD_SET)
        template = app_settings.EMAIL_TEMPLATE_PASSWORD_SET
        subject = app_settings.EMAIL_SUBJECT_PASSWORD_SET
        return self.send(subject, template, email_context, *args, **kwargs)

    def send_password_reset_email(self, info, *args, **kwargs):
        email_context = self.get_email_context(
            info, app_settings.PASSWORD_RESET_PATH_ON_EMAIL, TokenAction.PASSWORD_RESET
        )
        template = app_settings.EMAIL_TEMPLATE_PASSWORD_RESET
        subject = app_settings.EMAIL_SUBJECT_PASSWORD_RESET
        return self.send(subject, template, email_context, *args, **kwargs)

    def send_secondary_email_activation(self, info, email):
        if not self.email_is_free(email):
            raise EmailAlreadyInUseError
        email_context = self.get_email_context(
            info,
            app_settings.ACTIVATION_SECONDARY_EMAIL_PATH_ON_EMAIL,
            TokenAction.ACTIVATION_SECONDARY_EMAIL,
            secondary_email=email,
        )
        template = app_settings.EMAIL_TEMPLATE_SECONDARY_EMAIL_ACTIVATION
        subject = app_settings.EMAIL_SUBJECT_SECONDARY_EMAIL_ACTIVATION
        return self.send(subject, template, email_context, recipient_list=[email])

    @classmethod
    def email_is_free(cls, email) -> bool:
        return not UserModel._default_manager.filter(
            models.Q(**{UserModel.EMAIL_FIELD: email}) | models.Q(status__secondary_email=email)  # type: ignore
        ).exists()

    @classmethod
    def clean_email(cls, email=False):
        if email:
            if cls.email_is_free(email) is False:
                raise EmailAlreadyInUseError

    @classmethod
    def verify(cls, email, token):
        # payload = get_token_payload(token, TokenAction.ACTIVATION, app_settings.EXPIRATION_ACTIVATION_TOKEN)
        payload = OTPCode.verify_token_code(email, token, app_settings.EXPIRATION_ACTIVATION_TOKEN)
        #user = UserModel._default_manager.get(**payload)
        user = payload.user
        user_status = cls.objects.get(user=user)
        if user_status.verified is False:
            user_status.verified = True
            user_status.save(update_fields=["verified"])
            payload.used = True
            payload.save(update_fields=['used'])
            user_verified.send(sender=cls, user=user)
        else:
            raise UserAlreadyVerifiedError

    @classmethod
    def verify_secondary_email(cls, token):
        payload = get_token_payload(
            token,
            TokenAction.ACTIVATION_SECONDARY_EMAIL,
            app_settings.EXPIRATION_SECONDARY_EMAIL_ACTIVATION_TOKEN,
        )
        secondary_email = payload.pop("secondary_email")
        if not cls.email_is_free(secondary_email):
            raise EmailAlreadyInUseError
        user = UserModel._default_manager.get(**payload)
        user_status = cls.objects.get(user=user)
        user_status.secondary_email = secondary_email
        user_status.save(update_fields=["secondary_email"])

    @classmethod
    def unarchive(cls, user):
        if user.status.archived is True:
            user.status.archived = False
            user.status.save()

    @classmethod
    def archive(cls, user):
        user_status = cls.objects.get(user=user)
        if user_status.archived is False:
            user_status.archived = True
            user_status.save(update_fields=["archived"])

    def swap_emails(self):
        if not self.secondary_email:
            raise WrongUsageError
        with transaction.atomic():
            EMAIL_FIELD = UserModel.EMAIL_FIELD  # type: ignore
            primary = getattr(self.user, EMAIL_FIELD)
            setattr(self.user, EMAIL_FIELD, self.secondary_email)
            self.secondary_email = primary
            self.user.save(update_fields=[EMAIL_FIELD])
            self.save(update_fields=["secondary_email"])

    def remove_secondary_email(self):
        if not self.secondary_email:
            raise WrongUsageError
        with transaction.atomic():
            self.secondary_email = None
            self.save(update_fields=["secondary_email"])
