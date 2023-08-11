from rest_framework import serializers
from rest_framework.fields import empty
from .models import *


def required(value):
    if value is None:
        raise serializers.ValidationError('This field is required')


class DonorSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(validators=[required])
    last_name = serializers.CharField(validators=[required])
    phone_number = serializers.CharField(validators=[required])
    email = serializers.EmailField(validators=[required])
    password = serializers.CharField(validators=[required])
    dob = serializers.CharField(validators=[required])
    gender = serializers.CharField(validators=[required])
    # university_name = serializers.CharField(validators=[required])
    seat_no = serializers.CharField(validators=[required])
    role = serializers.CharField(validators=[required])

    class Meta:
        model = Donor
        fields = ['id', 'first_name', 'last_name', 'email', 'password', 'phone_number', 'gender', 'dob',
                  'university_name', 'seat_no', 'role', 'city', 'address', 'blood_group',
                  'no_of_donations', 'image_url']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    class Meta:
        model = Donor
        fields = ['email', 'password']


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        model = Donor
        fields = ['email']


class UpdatePasswordSerializer(serializers.Serializer):
    password = serializers.CharField()
    new_password = serializers.CharField()

    class Meta:
        model = Donor
        fields = ['password', 'new_password', ]


class UniversityNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = UniversityName
        fields = "__all__"


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = "__all__"


class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = "__all__"


class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = "__all__"


class DonationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Donation
        fields = "__all__"
