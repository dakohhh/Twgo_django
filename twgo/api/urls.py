from django.urls import path
from .views import *

urlpatterns = [
    path('', index, name='index'),
    path("register-user/", RegisterUserApi.as_view(), name="register-user"),
    path("register-admin/", RegisterAdminApi.as_view(), name="register-admin"),
    path("login-user/", LoginUserApi.as_view(), name="login-user"),
    path("login-admin/", LoginAdminApi.as_view(), name="login-admin"),
    path("login-superadmin/", LoginSuperAdminApi.as_view(), name="login-superadmin"),
    path("logout/", LogoutApi.as_view(), name="logout"),
    path("user/", UserApi.as_view(), name="user"),
    path('info/', UserInfo.as_view(), name='info'),
    path("create-project/", ProjectCreateView.as_view(), name="create-project"),
    path('projects/', ProjectListView.as_view(), name='project-list'),
    path('projects/accept/<int:project_id>/',
         AcceptProjectView.as_view(), name='accept-project'),
    path('projects/reject/<int:project_id>/',
         RejectProjectView.as_view(), name='reject-project'),
    path('balance/', BalanceView.as_view(), name='balance'),
    path('notifications/', NotificationListView.as_view(),
         name='get_notifications'),
]
