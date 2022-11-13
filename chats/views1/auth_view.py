import json

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.contrib.auth.models import User
from django.core import serializers
from django.http import HttpResponse

# Create your views here.
from django.shortcuts import render
from rest_framework import generics
from rest_framework.authentication import TokenAuthentication, BasicAuthentication, SessionAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import api_view
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from chats.authentication import BearerAuthentication
from chats.serializers import RegistrationSerializer, UsersWithMessageSerializer, UserSerializer


class Login(ObtainAuthToken):

    def post(self, request):

        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        # self.__change_status(user)
        serialize_user = UserSerializer(user, many=False)
        return Response({
            'token': token.key,
            'user': serialize_user.data,
        })

    # def __change_status(self, user: User):

    #     profile = user.profile
    #     profile.online = True
    #     profile.save()
    #     notify_others(user)


class RegisterView(CreateAPIView):
    serializer_class = RegistrationSerializer

    def post(self, request, *args, **kwargs):
        super(RegisterView, self).post(request, *args, **kwargs)
        return Response({'message': 'Registration success, now you can login'})


class LogOutView(APIView):
    authentication_classes = [SessionAuthentication, BasicAuthentication, BearerAuthentication]

    def post(self, request, format=None):
        profile = request.user.profile
        profile.online = False
        profile.save()
        print("user la ",request.user)
        # notify_others(request.user)
        return Response({'message': 'logout'})


class UsersView(generics.ListAPIView):
    serializer_class = UsersWithMessageSerializer
    authentication_classes = [SessionAuthentication, BasicAuthentication, BearerAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        users = User.objects.exclude(pk=self.request.user.pk).order_by('-profile__online').all()
        return users


# def notify_others(user: User):
#     serializer = UserSerializer(user, many=False)
#     channel_layer = get_channel_layer()
#     print('noti neeeeeee')
#     async_to_sync(channel_layer.group_send)(
#         'notification', {
#             'type': 'user_online',
#             'message': serializer.data
#         }
#     )


def room(request, room_name):
    return render(request, "testroom.html", {"room_name": room_name})

# Change Password
from rest_framework import status
from chats.serializers import ChangePasswordSerializer
from rest_framework.permissions import IsAuthenticated   

class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User

    authentication_classes = [SessionAuthentication, BasicAuthentication, BearerAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# from django.dispatch import receiver
# from django.urls import reverse
# from django_rest_passwordreset.signals import reset_password_token_created
# from django.core.mail import send_mail  
# @receiver(reset_password_token_created)
# def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):

#     email_plaintext_message = "{}?token={}".format(reverse('password_reset:reset-password-request'), reset_password_token.key)

#     send_mail(
#         # title:
#         "Password Reset for {title}".format(title="Some website title"),
#         # message:
#         email_plaintext_message,
#         # from:
#         "noreply@somehost.local",
#         # to:
#         [reset_password_token.user.email]
#     )