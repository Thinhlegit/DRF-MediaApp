from django.urls import path

# from chats.views.auth_view import *
from rest_framework.authtoken import views
from django.urls import path, include
from chats.views1.call_view import *
from chats.views1.message_view import *
from chats.views1.auth_view import *
# from chat_app import settings

urlpatterns = [
    path('api-token-auth/', views.obtain_auth_token),
    path('login/', Login.as_view()),
    path('registration/', RegisterView.as_view()),
    path('logout/', LogOutView.as_view()),
    path('users/', UsersView.as_view()),
    path('message/', MessageView.as_view()),
    path('start-call/', StartCall.as_view()),
    path('end-call/', EndCall.as_view()),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    # path('password_reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),
   
    # path('test-socket/', test_socket),
    # path("<str:room_name>/",room , name="room"),
]
