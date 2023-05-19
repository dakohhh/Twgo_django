from django.urls import path
from . import views

urlpatterns = [
    path("register-user/", views.RegisterUserApi.as_view(), name="register-user"),
    path("register-admin/", views.RegisterAdminApi.as_view(), name="register-admin"),
    path("login-user/", views.LoginUserApi.as_view(), name="login-user"),
    path("login-admin/", views.LoginAdminApi.as_view(), name="login-admin"),
    path("logout/", views.LogoutApi.as_view(), name="logout"),
    path("user/", views.UserApi.as_view(), name="user"),
    path("create-project/", views.ProjectCreateView.as_view(), name="create-project"),
    path('balance/', views.BalanceView.as_view(), name='balance'),
]
