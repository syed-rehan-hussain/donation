import string
from random import randint
import random

from django.shortcuts import render
from rest_framework import viewsets, generics, status
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import authenticate, login, logout
from rest_framework.response import Response
import requests
from blood_donation import settings
from .hooks import AccountDefaultHookSet
from .models import *
from django.utils.crypto import get_random_string

from .serializers import *


def generate_password():
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(10))
    return result_str


# Create your views here.
class SignUpView(generics.CreateAPIView):
    serializer_class = DonorSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            if Donor.objects.filter(email=request.data['email']).exists():
                return Response({'message': 'Email is already Exist'}, status=status.HTTP_409_CONFLICT)

            if 'password' in request.data:
                hashed_password = make_password(request.data['password'])

            response = self.create(request, *args, **kwargs)
            user = User.objects.filter(pk=response.data['id'], is_deleted=False)
            user.update(password=hashed_password)
            ctx = response.data

            del response.data["password"]
            response.data['gender'] = Donor.TYPE_CHOICES[int(response.data['gender']) - 1][1]
            response.data['role'] = Donor.ROLE[int(response.data['role']) - 1][1]


            # response.data['registration_date'] = response.data["created_at"]

            # email_context = {'email': request.data['email'], 'first_name': response.data['first_name'],
            #                  'last_name': response.data['last_name']}
            # hook_set.registration_email(email_context)
            # emailverify_context = {'email': response.data['email'], 'secret_hash': response.data['secret_hash'] , 'domain':request.get_host()}
            # hook_set.referral_invitation_email(emailverify_context)
            return Response(ctx, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class SignInView(generics.CreateAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            serializer = LoginSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                user = authenticate(request, username=request.data['email'], password=request.data['password'])
                if user is not None:
                    if user.banned:
                        return Response({"message": "Your account is suspended."}, status=status.HTTP_401_UNAUTHORIZED)
                    else:
                        login(request, user)
                        if user.role == '3':
                            donor = Donor.objects.get(user_ptr=user)
                            ctx = []
                            r = requests.post(
                                settings.base_url_auth + '/o/token/',
                                data={
                                    'grant_type': 'password',
                                    'username': request.data['email'],
                                    'password': request.data['password'],
                                    'client_id': settings.CLIENT_ID,
                                    'client_secret': settings.CLIENT_SECRET,
                                },
                            )
                            ctx = {'id': user.pk,
                                   'first_name': user.first_name,
                                   'last_name': user.last_name,
                                   'email': user.email,
                                   'phone_number': user.phone_number,
                                   'dob': donor.dob,
                                   # 'gender': Donor.TYPE_CHOICES[int(user.gender) - 1][1],
                                   'university_name': donor.university_name.name,
                                   'seat_no': donor.seat_no,
                                   'access_token': r.json()['access_token'],
                                   'expires_in': r.json()['expires_in'],
                                   'token_type': r.json()['token_type'],
                                   'scope': r.json()['scope'],
                                   'refresh_token': r.json()['refresh_token']

                                   }


                        # elif user.is_patient:
                        #     patient = Patient.objects.get(user_ptr=user)
                        #     date_of_birth = patient.date_of_birth
                        #     # Add other patient-specific fields as needed
                        #
                        # else:
                        #     # Handle other user types if necessary
                        #     date_of_birth = None

                        return Response(ctx, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "Invalid Email or Password"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset = Donor.objects.filter(is_deleted=False)
    serializer_class = DonorSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, *args, **kwargs):
        try:
            query_set = Donor.objects.filter(pk=pk, is_deleted=False)
            if query_set.exists():

                user_detail = query_set.values('id', 'first_name', 'last_name', 'email', 'phone_number', 'image_url',
                                               'dob', 'gender', 'city', 'address', 'university_name', 'seat_no',
                                               'blood_group', 'no_of_donations')
                university_name = UniversityName.objects.get(pk=user_detail[0]["university_name"], is_deleted=False)

                ctx = {'id': user_detail[0]["id"],
                       'first_name': user_detail[0]["first_name"],
                       'last_name': user_detail[0]["last_name"],
                       'email': user_detail[0]["email"],
                       'phone_number': user_detail[0]["phone_number"],
                       'image_url': settings.base_url_auth + "/media/" + user_detail[0]["image_url"],
                       'dob': user_detail[0]["dob"],
                       'gender': Donor.TYPE_CHOICES[int(user_detail[0]["gender"]) - 1][1],
                       'city': user_detail[0]["city"],
                       'address': user_detail[0]["address"],
                       'university_name': university_name.name,
                       'seat_no': user_detail[0]["seat_no"],
                       'blood_group': user_detail[0]["blood_group"],
                       'no_of_donations': user_detail[0]["no_of_donations"]}

                return Response(ctx, status=status.HTTP_200_OK)
            else:

                return Response({'message': 'Donor does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, *args, **kwargs):
        try:
            user_detail = Donor.objects.filter(pk=pk, is_deleted=False)
            if user_detail.exists():
                response = self.partial_update(request, *args, **kwargs)
                response.data["gender"] = Donor.TYPE_CHOICES[int(response.data["gender"]) - 1][1]
                del response.data["password"]
                return response
            else:
                return Response({'message': 'Donor does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# user change his password
class UserChangePasswordView(generics.UpdateAPIView):
    serializer_class = UpdatePasswordSerializer

    def put(self, request, user_id, *args, **kwargs):
        try:
            serializer = UpdatePasswordSerializer(data=request.data)

            serializer.is_valid(raise_exception=True)

            if request.data["password"] != request.data["new_password"]:

                user_details = User.objects.filter(pk=user_id, is_deleted=False)
                if user_details.count() > 0:
                    if check_password(request.data['password'], user_details[0].password):
                        user_details.update(password=make_password(request.data["new_password"]))

                        return Response({"message": "password update successfully"}, status=status.HTTP_200_OK)
                    else:
                        return Response({"message": "Invalid password"}, status=status.HTTP_403_FORBIDDEN)

                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            else:
                return Response({"message": "Use an other password!"}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UserForgotPasswordView(generics.CreateAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            serializer = ForgotPasswordSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user_details = User.objects.filter(email=request.data['email'], is_deleted=False)

            if user_details.count() > 0:
                gen_pass = generate_password()
                user = user_details.first()
                new_pass = gen_pass
                user.password = make_password(new_pass)
                user.save()
                email_context = {'email': user.email, 'new_password': new_pass}
                AccountDefaultHookSet.forgot_password_email(self, email_context)
                return Response(
                    {"message": "password send on Register email address successfully"},
                    status=status.HTTP_200_OK)

            return Response({"message": "Email does not exist"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ListDonorsView(generics.ListAPIView):
    queryset = Donor.objects.filter(is_deleted=False, role='3')
    serializer_class = DonorSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            query_set = Donor.objects.filter(is_deleted=False, role='3')
            if query_set.exists():
                result = []
                user_detail = query_set.values('id', 'first_name', 'last_name', 'email', 'phone_number', 'image_url',
                                               'dob', 'gender', 'city', 'address', 'university_name', 'seat_no',
                                               'blood_group', 'no_of_donations')
                for user in user_detail:
                    university_name = UniversityName.objects.get(pk=user_detail[0]["university_name"], is_deleted=False)
                    ctx = {'id': user["id"],
                           'first_name': user["first_name"],
                           'last_name': user["last_name"],
                           'email': user["email"],
                           'phone_number': user["phone_number"],
                           'image_url': settings.base_url_auth + "/media/" + user["image_url"],
                           'dob': user["dob"],
                           'gender': Donor.TYPE_CHOICES[int(user["gender"]) - 1][1],
                           'city': user["city"],
                           'address': user["address"],
                           'university_name': university_name.name,
                           'seat_no': user["seat_no"],
                           'blood_group': user["blood_group"],
                           'no_of_donations': user["no_of_donations"]}
                    result.append(ctx)
                return Response(result, status=status.HTTP_200_OK)
            else:

                return Response({'message': 'Donor does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ListHospitalDonorsView(generics.ListAPIView):
    queryset = Donor.objects.filter(is_deleted=False, role='3')
    serializer_class = DonorSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, *args, **kwargs):
        try:
            # query_set = Donor.objects.filter(is_deleted=False, role='3')
            query_set = Donation.objects.filter(is_deleted=False, hospital_name=pk).values('donor').distinct()
            if query_set.exists():
                result = []
                for user in query_set:
                    donor = Donor.objects.get(pk=user['donor'], is_deleted=False)
                    university_name = UniversityName.objects.get(pk=donor.university_name_id, is_deleted=False)
                    ctx = {'id': donor.id,
                           'first_name': donor.first_name,
                           'last_name': donor.last_name,
                           'email': donor.email,
                           'phone_number': donor.phone_number,
                           'dob': donor.dob,
                           'gender': Donor.TYPE_CHOICES[int(donor.gender) - 1][1],
                           'city': donor.city,
                           'address': donor.address,
                           'university_name': university_name.name,
                           'seat_no': donor.seat_no,
                           'blood_group': donor.blood_group,
                           'no_of_donations': donor.no_of_donations}
                    result.append(ctx)
                return Response(result, status=status.HTTP_200_OK)
            else:

                return Response({'message': 'Donor does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UniversityNameView(generics.ListCreateAPIView):
    queryset = UniversityName.objects.filter(is_deleted=False)
    serializer_class = UniversityNameSerializer
    permission_classes = [IsAuthenticated]


class UniversityNameRUDView(generics.RetrieveUpdateDestroyAPIView):
    queryset = UniversityName.objects.filter(is_deleted=False)
    serializer_class = UniversityNameSerializer
    permission_classes = [IsAuthenticated]


class CategoryView(generics.ListCreateAPIView):
    queryset = Category.objects.filter(is_deleted=False)
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]


class CategoryRUDView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Category.objects.filter(is_deleted=False)
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]


class PostView(generics.ListCreateAPIView):
    queryset = Post.objects.filter(is_deleted=False)
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            query_set = Post.objects.filter(is_deleted=False)
            if query_set.exists():
                result = []
                post_detail = query_set.values('id', 'image_url', 'title', 'slug', 'author', 'category',
                                               'content', 'status')
                for post in post_detail:
                    category_name = Category.objects.get(pk=post_detail[0]["category"], is_deleted=False)

                    ctx = {'id': post["id"],
                           'image_url': settings.base_url_auth+"/media/"+post_detail[0]["image_url"],
                           'title': post["title"],
                           'slug': post["slug"],
                           'author': post["author"],
                           'category': category_name.name,
                           'content': post["content"],
                           'status': Post.STATUS[int(post["status"]) - 1][1]
                           }
                    result.append(ctx)
                return Response(result, status=status.HTTP_200_OK)

            else:
                return Response({'message': 'Blog Post does not exist'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class PublishedPostView(generics.ListAPIView):
    queryset = Post.objects.filter(is_deleted=False, status='2')
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            query_set = Post.objects.filter(is_deleted=False, status='2')
            if query_set.exists():
                result = []
                post_detail = query_set.values('id', 'image_url', 'title', 'slug', 'author', 'category',
                                               'content', 'status')
                for post in post_detail:
                    category_name = Category.objects.get(pk=post_detail[0]["category"], is_deleted=False)

                    ctx = {'id': post["id"],
                           'image_url': settings.base_url_auth+"/media/"+post_detail[0]["image_url"],
                           'title': post["title"],
                           'slug': post["slug"],
                           'author': post["author"],
                           'category': category_name.name,
                           'content': post["content"],
                           'status': Post.STATUS[int(post["status"]) - 1][1]
                           }
                    result.append(ctx)
                return Response(result, status=status.HTTP_200_OK)

            else:
                return Response({'message': 'Blog Post does not exist'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class PostRUDView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Post.objects.filter(is_deleted=False)
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, *args, **kwargs):
        try:
            query_set = Post.objects.filter(pk=pk, is_deleted=False)
            if query_set.exists():
                post_detail = query_set.values('id', 'image_url', 'title', 'slug', 'author', 'category',
                                               'content', 'status')
                category_name = Category.objects.get(pk=post_detail[0]["category"], is_deleted=False)

                ctx = {'id': post_detail[0]["id"],
                       'image_url': settings.base_url_auth+"/media/"+post_detail[0]["image_url"],
                       'title': post_detail[0]["title"],
                       'slug': post_detail[0]["slug"],
                       'author': post_detail[0]["author"],
                       'category': category_name.name,
                       'content': post_detail[0]["content"],
                       'status': Post.STATUS[int(post_detail[0]["status"]) - 1][1]
                       }
                return Response(ctx, status=status.HTTP_200_OK)

            else:
                return Response({'message': 'Blog Post does not exist'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class EventView(generics.ListCreateAPIView):
    queryset = Event.objects.filter(is_deleted=False)
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]


class PublishedEventView(generics.ListAPIView):
    queryset = Event.objects.filter(is_deleted=False, status="2")
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]


class EventRUDView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Event.objects.filter(is_deleted=False)
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]


class DonationView(generics.ListCreateAPIView):
    queryset = Donation.objects.filter(is_deleted=False)
    serializer_class = DonationSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            query_set = Donation.objects.filter(is_deleted=False)
            if query_set.exists():
                result = []
                donation_detail = query_set.values('id', 'donor', 'hospital_name', 'blood_group', 'quantity', 'report',
                                                   'donation_date', 'expiry_date')
                for donation in donation_detail:
                    donor = Donor.objects.get(pk=donation_detail[0]["donor"], is_deleted=False)
                    hospital = Hospital.objects.get(pk=donation_detail[0]["hospital_name"], is_deleted=False)

                    ctx = {'id': donation["id"],
                           'donor': donor.email,
                           'hospital_name': hospital.hospital_name,
                           'blood_group': donation["blood_group"],
                           'quantity': donation["quantity"],
                           'report': donation["report"],
                           'donation_date': donation["donation_date"],
                           'expiry_date': donation["expiry_date"]
                           }
                    result.append(ctx)
                return Response(result, status=status.HTTP_200_OK)

            else:
                return Response({'message': 'Donation does not exist'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class DonationRUDView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Donation.objects.filter(is_deleted=False)
    serializer_class = DonationSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, *args, **kwargs):
        try:
            query_set = Donation.objects.filter(pk=pk, is_deleted=False)
            if query_set.exists():
                result = []
                donation_detail = query_set.values('id', 'donor', 'hospital_name', 'blood_group', 'quantity', 'report',
                                                   'donation_date', 'expiry_date')
                donor = Donor.objects.get(pk=donation_detail[0]["donor"], is_deleted=False)
                hospital = Hospital.objects.get(pk=donation_detail[0]["hospital_name"], is_deleted=False)

                ctx = {'id': donation_detail[0]["id"],
                       'donor': donor.email,
                       'hospital_name': hospital.hospital_name,
                       'blood_group': donation_detail[0]["blood_group"],
                       'quantity': donation_detail[0]["quantity"],
                       'report': donation_detail[0]["report"],
                       'donation_date': donation_detail[0]["donation_date"],
                       'expiry_date': donation_detail[0]["expiry_date"]
                       }
                return Response(ctx, status=status.HTTP_200_OK)

            else:
                return Response({'message': 'Blog Post does not exist'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class DashboardView(generics.ListAPIView):
    queryset = Donor.objects.filter(is_deleted=False)
    serializer_class = DonorSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:

            donor = Donor.objects.filter(is_deleted=False).count()
            event = Event.objects.filter(is_deleted=False).count()
            blog = Post.objects.filter(is_deleted=False).count()
            Volunteer = User.objects.filter(is_deleted=False, role=2).count()
            donation = Donation.objects.filter(is_deleted=False).count()

            ctx = {
                   'donor': donor,
                   'event': event,
                   'blog': blog,
                   'Volunteer': Volunteer,
                   'donation': donation,
                   }
            return Response(ctx, status=status.HTTP_200_OK)

            # return Response({'message': 'Blog Post does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# // T o k e n i z a t i on // #

@permission_classes([AllowAny])
class Token(generics.CreateAPIView):
    ''' Gets tokens with username and password. Input should be in the format:{"username": "username", "password":
    "1234abcd"} '''

    def post(self, request, *args, **kwargs):
        r = requests.post(
            settings.base_url_auth + '/o/token/',
            data={
                'grant_type': 'password',
                'username': request.data['email'],
                'password': request.data['password'],
                'client_id': settings.CLIENT_ID,
                'client_secret': settings.CLIENT_SECRET,
            },
        )
        return Response(r.json())


@permission_classes([AllowAny])
class RefreshToken(generics.CreateAPIView):
    '''
    Registers user to the server. Input should be in the format:
    {"refresh_token": "<token>"}
    '''

    def post(self, request, *args, **kwargs):
        r = requests.post(
            settings.base_url_auth + '/o/token/',
            data={
                'grant_type': 'refresh_token',
                'refresh_token': request.data['refresh_token'],
                'client_id': settings.CLIENT_ID,
                'client_secret': settings.CLIENT_SECRET,
            },
        )
        return Response(r.json())


@permission_classes([AllowAny])
class RevokeToken(generics.CreateAPIView):
    '''
    Method to revoke tokens.
    {"token": "<token>"}
    '''

    def post(self, request, *args, **kwargs):
        r = requests.post(
            settings.base_url_auth + '/o/revoke_token/',
            data={
                'token': request.data['token'],
                'client_id': settings.CLIENT_ID,
                'client_secret': settings.CLIENT_SECRET,
            },
        )
        # If it goes well return sucess message (would be empty otherwise)
        if r.status_code == requests.codes.ok:
            return Response({'message': 'token revoked'}, r.status_code)
        # Return the error if it goes badly
        return Response(r.json(), r.status_code)
