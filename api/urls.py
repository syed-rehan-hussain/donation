from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include

from api.views import *

urlpatterns = [
    path('sign-up', SignUpView.as_view(), name='user_sign_up'),
    path('sign-in', SignInView.as_view(), name='user_sign_in'),
    path('users/<int:user_id>/change-password', UserChangePasswordView.as_view(), name='user_change_password'),
    path('users/forgot-password', UserForgotPasswordView.as_view(), name="user_forgot_password"),
    path('list_donors', ListDonorsView.as_view(), name='list_donors'),
    path('list_hospital_donors/<int:pk>', ListHospitalDonorsView.as_view(), name='list_donors_by_hospital'),
    path('university', UniversityNameView.as_view(), name='university'),
    path('university/<int:pk>', UniversityNameRUDView.as_view(), name='university_details'),
    path('users/<int:pk>/profile', UserDetailView.as_view(), name='users_details'),
    path('category', CategoryView.as_view(), name='category'),
    path('category/<int:pk>', CategoryRUDView.as_view(), name='category_details'),
    path('post', PostView.as_view(), name='post'),
    path('publish_post', PublishedPostView.as_view(), name='publish_post'),
    path('post/<int:pk>', PostRUDView.as_view(), name='post_details'),
    path('event', EventView.as_view(), name='event'),
    path('publish_event', PublishedEventView.as_view(), name='publish_event'),
    path('event/<int:pk>', EventRUDView.as_view(), name='event_details'),
    path('donation', DonationView.as_view(), name='donation'),
    path('donation/<int:pk>', DonationRUDView.as_view(), name='donation_details'),
    path('dashboard', DashboardView.as_view(), name='dashboard'),


    # *****************************Aouth2.0 Authentications*************************
    path('token', Token.as_view(), name='token'),
    path('token/refresh', RefreshToken.as_view(), name='token_refresh'),
    path('token/revoke', RevokeToken.as_view(), name='token_revoke'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
