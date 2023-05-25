from django.http import JsonResponse
from django.views import View
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import response, exceptions, permissions, generics, status
from decimal import Decimal, InvalidOperation
from .models import *
from . import serializer as user_serializer
from . import services, authentication


def index(request):
    response = JsonResponse(
        'Hi, you are welcome to TWGO backend . . .', safe=False)
    return response


class RegisterUserApi(APIView):
    def post(self, request):
        serializer = user_serializer.UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.validated_data
        resp = services.create_user(user_dc=data)

        if resp.get('success'):
            serializer.instance = resp.get('data')
            user = User.objects.get(id=serializer.data['id'])
            notification = Notifications(
                user=user, message='Welcome to twgo', details='We are delighted to have you here...')
            notification.save()

        return resp


class RegisterAdminApi(APIView):
    def post(self, request):
        serializer = user_serializer.UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.validated_data
        resp = services.create_admin(user_dc=data)

        if resp.get('success'):
            serializer.instance = resp.get('data')
            user = User.objects.get(id=serializer.data['id'])
            notification = Notifications(
                user=user, message='Welcome to twgo dear Admin.', details='We are delighted to have you here...')
            notification.save()

        return resp


class LoginUserApi(APIView):
    def post(self, request):
        email = request.data["email"]
        password = request.data["password"]

        user = services.user_email_selector(email=email)

        if user is None:
            raise exceptions.AuthenticationFailed("Invalid Credentials")

        if not user.check_password(raw_password=password):
            raise exceptions.AuthenticationFailed("Invalid Credentials")

        if user.is_staff == False and user.is_superuser == False:
            token = services.create_token(user_id=user.id)
            resp = response.Response(
                data={'success': True, 'email': user.email, 'token': token})
            resp.set_cookie(key="jwt", value=token, httponly=True)
        else:
            resp = response.Response(
                data={'success': False, 'message': 'Invalid Credentials'})

        return resp


class LoginAdminApi(APIView):
    def post(self, request):
        email = request.data["email"]
        password = request.data["password"]

        user = services.user_email_selector(email=email)

        if user is None:
            raise exceptions.AuthenticationFailed("Invalid Credentials")

        if not user.check_password(raw_password=password):
            raise exceptions.AuthenticationFailed("Invalid Credentials")

        if user.is_staff == True and user.is_superuser == False:
            token = services.create_token(user_id=user.id)
            resp = response.Response(
                data={'success': True, 'email': user.email, 'token': token})
            resp.set_cookie(key="jwt", value=token, httponly=True)
        else:
            resp = response.Response(
                data={'success': False, 'message': 'User is not admin'})

        return resp


class LoginSuperAdminApi(APIView):
    def post(self, request):
        email = request.data["email"]
        password = request.data["password"]

        user = services.user_email_selector(email=email)

        if user is None:
            raise exceptions.AuthenticationFailed("Invalid Credentials")

        if not user.check_password(raw_password=password):
            raise exceptions.AuthenticationFailed("Invalid Credentials")

        if user.is_staff == True and user.is_superuser == True:
            token = services.create_token(user_id=user.id)
            resp = response.Response(
                data={'success': True, 'email': user.email, 'token': token})
            resp.set_cookie(key="jwt", value=token, httponly=True)
        else:
            resp = response.Response(
                data={'success': False, 'message': 'User is not superadmin'})

        return resp


class UserApi(APIView):
    """
    This endpoint can only be used
    if the user is authenticated
    """

    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        user = request.user

        serializer = user_serializer.UserSerializer(user)

        return response.Response(serializer.data)


class LogoutApi(APIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        resp = response.Response()
        resp.delete_cookie("jwt")
        resp.data = {"message": "so long farewell"}

        return resp


class ProjectCreateView(generics.CreateAPIView):
    queryset = Project.objects.all()
    serializer_class = user_serializer.ProjectSerializer
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def perform_create(self, serializer):
        project = serializer.save(user=self.request.user, status='pending')
        # Perform additional actions here, such as sending notifications to admins

        # Set the initial admin to None
        project.admin = None
        project.save()


class ProjectListView(View):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        projects = Project.objects.filter(status='pending')
        project_list = []

        for project in projects:
            project_data = {
                'id': project.id,
                'title': project.title,
                'department': project.department,
                'category': project.category,
                'budget': project.budget,
                'service_type': project.service_type,
                'delivery_date': project.delivery_date,
                'user': project.user.username,
                'admin': project.admin.username if project.admin else None,
                'status': project.status
            }
            project_list.append(project_data)

        return JsonResponse(project_list, safe=False)


class AcceptProjectView(APIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, project_id):
        try:
            project = Project.objects.get(id=project_id)
        except Project.DoesNotExist:
            return JsonResponse({'error': 'Project not found'}, status=404)

        if project.status != 'pending':
            return JsonResponse({'error': 'Only pending projects can be accepted'}, status=400)

        project.status = 'accepted'
        project.admin = request.user
        project.save()

        user = User.objects.get(id=project.user.id)

        notification = Notifications(
            user=user, message='You project has been accepted', details=f'"{project.title}" has been accepted. Proceed to chat with the admin.')
        notification.save()

        return JsonResponse({'message': 'Project accepted'}, status=200)


class RejectProjectView(APIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, project_id):
        try:
            project = Project.objects.get(id=project_id)
        except Project.DoesNotExist:
            return JsonResponse({'error': 'Project not found'}, status=404)

        if project.status != 'rejected':
            return JsonResponse({'error': 'Project already rejected'}, status=400)

        project.status = 'rejected'
        project.admin = request.user
        project.save()

        return JsonResponse({'message': 'Project rejected'}, status=200)


class BalanceView(APIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        funds, created = Funds.objects.get_or_create(user=request.user)
        serializer = user_serializer.FundsSerializer(funds)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        funds, created = Funds.objects.get_or_create(user=request.user)

        amount = request.data.get('amount', None)
        action = request.data.get('action', None)

        if amount is None:
            return Response({'error': 'Please provide an amount to change the balance'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            amount = Decimal(amount)
        except InvalidOperation:
            return Response({'error': 'Invalid amount provided'}, status=status.HTTP_400_BAD_REQUEST)

        if action is None:
            return Response({'error': 'Please provide an action to perform on the balance (add/sub)'}, status=status.HTTP_400_BAD_REQUEST)

        if action not in ['add', 'sub']:
            return Response({'error': 'Invalid action provided. Only "add" or "sub" allowed.'}, status=status.HTTP_400_BAD_REQUEST)

        if action == 'add':
            funds.total_balance += amount
        elif action == 'sub':
            if funds.total_balance < amount:
                return Response({'error': 'Insufficient funds'}, status=status.HTTP_400_BAD_REQUEST)
            funds.total_balance -= amount

        funds.save()
        serializer = user_serializer.FundsSerializer(funds)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserInfo(APIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):

        user = request.user
        userserializer = user_serializer.UserSerializer(user)

        funds, created = Funds.objects.get_or_create(user=request.user)
        fundsserializer = user_serializer.FundsSerializer(funds)

        return Response(data={'info': userserializer.data, 'funds': fundsserializer.data}, status=status.HTTP_200_OK)


class NotificationListView(APIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        user = request.user
        notifications = Notifications.objects.filter(
            user=user).order_by('-created_at')
        data = []
        if notifications.exists():  # Check if notifications exist
            for notification in notifications:
                data.append({
                    'message': notification.message,
                    'is_read': notification.is_read,
                    'created_at': notification.created_at
                })
        return JsonResponse(data, safe=False)
