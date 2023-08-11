import os

from django.contrib.auth.base_user import BaseUserManager
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractUser


# Create your models here.
class CustomUserManager(BaseUserManager):
    use_in_migrations = True
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """

    def create_user(self, email, password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError(_('The Email must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(email, password, **extra_fields)


class BaseModel(models.Model):
    is_deleted = models.BooleanField(null=False, default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def delete(self):
        self.is_deleted = True
        self.save()

    def restore(self):
        self.is_deleted = False
        self.save()


class UniversityName(BaseModel):
    name = models.CharField(max_length=150, blank=True, )

    class Meta:
        db_table = 'UniversityName'
        verbose_name = 'UniversityName'
        verbose_name_plural = 'UniversityNames'

    def __str__(self):
        return self.name


class Category(BaseModel):
    name = models.CharField(max_length=150, blank=True, )

    class Meta:
        db_table = 'Category'
        verbose_name = 'Category'
        verbose_name_plural = 'Categories'

    def __str__(self):
        return self.name


def user_directory_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/user_<id>/<filename>
    return 'user_{0}/{1}'.format(instance.id, filename)


class User(AbstractUser, BaseModel):
    ROLE = (
        ('1', 'Admin'),
        ('2', 'Staff'),
        ('3', 'Donor'),
        ('4', 'Doctor'),
        ('5', 'Hospital'),
    )
    username = None
    role = models.CharField(max_length=10, null=True, choices=ROLE)
    email = models.EmailField(_('email address'), unique=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True, default=False)
    image_url = models.ImageField(upload_to=user_directory_path, blank=True, null=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    address = models.CharField(max_length=500, null=True, blank=True)
    banned = models.BooleanField(null=False, default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email


class Donor(User):
    TYPE_CHOICES = (
        ('1', 'Male'),
        ('2', 'Female'),
        ('3', 'Other'),
    )
    dob = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=10, null=True, choices=TYPE_CHOICES)
    university_name = models.ForeignKey(UniversityName, on_delete=models.CASCADE, null=True, related_name='university')
    seat_no = models.CharField(max_length=25, null=True, blank=True)
    blood_group = models.CharField(max_length=5, null=True, blank=True)
    no_of_donations = models.IntegerField(null=False, default=0)

    class Meta:
        db_table = 'donor'
        verbose_name = 'donor'
        verbose_name_plural = 'donors'
        ordering = ('-created_at',)

    def __str__(self):
        return self.email


class Hospital(User):
    hospital_name = models.CharField(max_length=100, null=True, blank=True)

    class Meta:
        db_table = 'hospital'
        verbose_name = 'hospital'
        verbose_name_plural = 'hospitals'

    def __str__(self):
        return self.hospital_name


def report_path(instance, filename):
    return 'user_{0}/{1}'.format(instance.donor_id, filename)


class Donation(BaseModel):
    donor = models.ForeignKey(Donor, on_delete=models.CASCADE, null=True, related_name='donor')
    hospital_name = models.ForeignKey(Hospital, on_delete=models.CASCADE, null=True, related_name='hospital')
    blood_group = models.CharField(max_length=15, null=True, blank=True)
    quantity = models.CharField(max_length=25, null=True, blank=True)
    report = models.FileField(upload_to=report_path, blank=True, null=True)
    donation_date = models.DateTimeField(null=True, blank=True)
    expiry_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'Donation'
        verbose_name = 'Donation'
        verbose_name_plural = 'Donations'

    def __str__(self):
        return self.blood_group


class Post(BaseModel):
    STATUS = (
        (1, "Draft"),
        (2, "Publish")
    )
    image_url = models.ImageField(upload_to='images/', blank=True, null=True)
    title = models.CharField(max_length=200, blank=True, unique=True)
    slug = models.SlugField(max_length=200, blank=True, unique=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blog_posts')
    category = models.ForeignKey(Category, on_delete=models.CASCADE, null=True, related_name='post_category')
    content = models.TextField()
    status = models.IntegerField(choices=STATUS, default=2)

    def __str__(self):
        return self.title


class Event(BaseModel):
    STATUS = (
        (1, "Draft"),
        (2, "Publish")
    )
    image_url = models.ImageField(upload_to='images/', blank=True, null=True)
    event_name = models.CharField(max_length=200, unique=True)
    date_of_event = models.DateField(null=True, blank=True)
    start_date = models.DateField(null=True, blank=True)
    start_time = models.TimeField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    address = models.CharField(max_length=500, null=True, blank=True)
    content = models.TextField()
    creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='event_creator')
    status = models.IntegerField(choices=STATUS, default=2)

    def __str__(self):
        return self.event_name
