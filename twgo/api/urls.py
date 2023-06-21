from .views import *
from django.urls import include, path
from drf_yasg.views import get_schema_view
from drf_yasg import openapi


schema_view = get_schema_view(
    openapi.Info(
        title="TWGO APP",
        default_version='v1',
        description="",
        terms_of_service="",
        contact=openapi.Contact(email=""),
        license=openapi.License(name=""),
    ),

    public=True,

    permission_classes=(permissions.AllowAny,),
)




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
    path('projects/user/', UserProjectHistoryView.as_view(),
         name='project-list-user'),
    path('projects/admin/', AdminProjectHistoryView.as_view(),
         name='project-list-user'),
    path('notifications/', NotificationsView.as_view(),
         name='project-list-user'),
    path('projects/accept/<int:project_id>/',
         AcceptProjectView.as_view(), name='accept-project'),
    path('projects/reject/<int:project_id>/',
         RejectProjectView.as_view(), name='reject-project'),
    path('balance/', BalanceView.as_view(), name='balance'),
    path('notifications/', NotificationListView.as_view(),
         name='get_notifications'),
    path('conversations/create/', ConversationCreateView.as_view(),
         name='create_conversation'),
    path('support-conversation/', SupportConversationView.as_view(),
         name='support-conversation'),
    path('get-work-conversation/', GetWorkConversationView.as_view(),
         name='get-work-conversation'),
    path('edu-consult-conversation/', EduConsultConversationView.as_view(),
         name='edu-consult-conversation'),
    path('accomondation-request-conversation/', AccomondationRequestConversationView.as_view(),
         name='accomondation-request-conversation'),
    path('conversations/send-message/',
         MessageCreateView.as_view(), name='send-message'),
    path('conversations/<int:conversation_id>/messages/',
         MessageListView.as_view(), name='message-list'),
    path('conversations/list/',
         ConversationListView.as_view(), name='message-list'),
     
     path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),

     path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),

     path('change-password/', ChangePasswordView.as_view(), name='change-password'),

     path('request-otp/', RequestOTPPasswordResetView.as_view(), name='request-otp'),

     path('validate-otp/', ValidateOTP.as_view(), name='validate-otp'),


     path('password-reset/', UpdatePasswordFromReset.as_view(), name='password-reset'),

     path("pay-with-card/", PaymentWithCard.as_view(), name="pay-with-card")


]
