import os
import json
import requests
from firebase_admin import auth
from django.http import JsonResponse
from django.views import View
from django.db.models import F
from rest_framework import status
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.views import APIView

from rest_framework import response, exceptions, permissions, generics, status
from decimal import Decimal, InvalidOperation
from .models import *
from . import serializer as user_serializer
from . import services, authentication

from .utils import fetchone, generate_hex, fetch_filter
import random
from django.contrib.auth.hashers import make_password, check_password
from firebase_admin import messaging
import stripe
from django.views.decorators.csrf import csrf_exempt
from .utils import get_conversion_rate
from decimal import Decimal

from rest_framework.permissions import IsAuthenticated 
from dotenv import load_dotenv


stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

load_dotenv()




def index(request):
    response = JsonResponse(
        'Hi, you are welcome to TWGO backend . . .', safe=False)
    return response


class RegisterUserApi(APIView):
    def post(self, request:Request):
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
            user.firebasetoken = request.data["firebasetoken"]
            user.save()
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
        project.admin = None
        project.save()

 


class UserProjectHistoryView(APIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        projects = Project.objects.filter(user=request.user).order_by('-id')
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
                'user': project.user.first_name+' ' + project.user.last_name,
                'admin': project.admin.first_name + ' ' + project.admin.last_name if project.admin else None,
                'status': project.status
            }
            project_list.append(project_data)

        return JsonResponse(project_list, safe=False)


class AdminProjectHistoryView(APIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        projects = Project.objects.filter(admin=request.user).order_by('-id')
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
                'user': project.user.first_name+' ' + project.user.last_name,
                'admin': project.admin.first_name + ' ' + project.admin.last_name if project.admin else None,
                'status': project.status
            }
            project_list.append(project_data)

        return JsonResponse(project_list, safe=False)


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
                'user': project.user.first_name+' ' + project.user.last_name,
                'user_id': project.user.id,
                'admin': project.admin.first_name + ' ' + project.admin.last_name if project.admin else None,
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

        return JsonResponse({'message': 'Project accepted', 'user_id': project.user.id}, status=200)


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


class NotificationsView(APIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        user = request.user
        notifications = Notifications.objects.filter(user=user)
        serializer = user_serializer.NotificationsSerializer(
            notifications, many=True)
        return Response(serializer.data)


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
            user=user).order_by(F('id').desc())
        notifications = notifications.values(
            'message', 'is_read', 'created_at')

        return JsonResponse(list(notifications), safe=False)


class ConversationCreateView(generics.CreateAPIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    queryset = Conversation.objects.all()
    serializer_class = user_serializer.ConversationSerializer


class SupportConversationView(generics.CreateAPIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def create(self, request, *args, **kwargs):
        current_user = request.user

        # Check if conversation already exists with the title 'Support' and current user as a participant
        conversation = Conversation.objects.filter(
            title='Support', participants=current_user).first()

        if not conversation:
            # Create a new conversation if it doesn't exist
            conversation = Conversation.objects.create(title='Support')
            conversation.participants.add(current_user)

        return Response({'conversation_id': conversation.id}, status=status.HTTP_200_OK)


class GetWorkConversationView(generics.CreateAPIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def create(self, request, *args, **kwargs):
        current_user = request.user
        superusers = User.objects.filter(is_superuser=True)

        # Check if conversation already exists with the given participants
        conversation = Conversation.objects.filter(
            title='Get Work', participants=current_user).first()

        if not conversation:
            # Create a new conversation if it doesn't exist
            conversation = Conversation.objects.create(title="Get Work")
            conversation.participants.add(current_user)
            conversation.participants.add(*superusers)

        return Response({'conversation_id': conversation.id}, status=status.HTTP_200_OK)


class EduConsultConversationView(generics.CreateAPIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def create(self, request, *args, **kwargs):
        current_user = request.user
        superusers = User.objects.filter(is_superuser=True)

        # Check if conversation already exists with the given participants
        conversation = Conversation.objects.filter(
            title='Edu Consult', participants=current_user).first()

        if not conversation:
            # Create a new conversation if it doesn't exist
            conversation = Conversation.objects.create(title="Edu Consult")
            conversation.participants.add(current_user)
            conversation.participants.add(*superusers)

        return Response({'conversation_id': conversation.id}, status=status.HTTP_200_OK)


class AccomondationRequestConversationView(generics.CreateAPIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def create(self, request, *args, **kwargs):
        current_user = request.user
        superusers = User.objects.filter(is_superuser=True)

        # Check if conversation already exists with the given participants
        conversation = Conversation.objects.filter(
            title='Accomondation Request', participants=current_user).first()

        if not conversation:
            # Create a new conversation if it doesn't exist
            conversation = Conversation.objects.create(
                title="Accomondation Request")
            conversation.participants.add(current_user)
            conversation.participants.add(*superusers)

        return Response({'conversation_id': conversation.id}, status=status.HTTP_200_OK)


class MessageCreateView(generics.CreateAPIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = user_serializer.MessageSerializer

    def perform_create(self, serializer):
        serializer.save(sender=self.request.user)

        # Retrieve the Firebase token for the recipient user
        conversation_id = serializer.validated_data['conversation_id']
        recipient_conversation = Conversation.objects.get(id=conversation_id)
        recipient = recipient_conversation.get_other_participant(
            self.request.user)
        recipient_uid = recipient.id  # Assuming the recipient user has a "uid" field
        user = auth.get_user_by_email(recipient_uid)
        # Assuming the recipient user has a "messaging_token" field for the Firebase token
        token = user.tokens.get('firebasetoken')

        # Send FCM notification to the recipient
        send_fcm_notification(token, recipient.first_name,
                              serializer.validated_data['content'])


def send_fcm_notification(token, title, body):
    # Construct the message payload
    message = messaging.Message(
        token=token,
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
    )

    # Send the message to the FCM server
    response = messaging.send(message)
    print('Successfully sent FCM notification:', response)


class MessageListView(generics.ListAPIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = user_serializer.MessageSerializer

    def get_queryset(self):
        user = self.request.user
        conversation_id = self.kwargs['conversation_id']

        # Clear unread messages for the current user in the conversation
        conversation = Conversation.objects.get(id=conversation_id)
        UnreadMessage.objects.filter(
            user=user, conversation=conversation).delete()

        return Message.objects.filter(conversation_id=conversation_id)


class ConversationListView(generics.ListAPIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = user_serializer.ConversationSerializer

    def get_queryset(self):
        user = self.request.user
        return Conversation.objects.filter(participants=user).order_by(F('id').desc())




class ChangePasswordView(generics.UpdateAPIView):
  
    serializer_class = user_serializer.ChangePasswordSerializer
    model = User
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():

            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            
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



class RequestOTPPasswordResetView(APIView):

    def post(self, request:Request, *args, **kwargs):

        serializer = user_serializer.OTPRequestSerializer(data=request.data)

        if serializer.is_valid():

            print(serializer.data.get("email"))

            email =  serializer.data.get("email")

            print(email)

            user = fetchone(User, email=email)

            if user == None:
                return Response({'message': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)


            otp = random.randint(1000, 9999)

            key=generate_hex(15)
            
            
            if OTP.objects.filter(user=user).exists():

                otp_klass = fetchone(OTP, user=user)

                otp_klass.otp = make_password(str(otp))

                otp_klass.key = key

                otp_klass.save()

            else:

                otp_klass = OTP(user=user, otp=make_password(str(otp)), key=key)

                otp_klass.save()
            
            send_mail(
                'Password Reset OTP For Twgo User',
                f'Your OTP: {otp}',
                settings.EMAIL_HOST,
                [email],
                fail_silently=False,
            )

            return Response({'message': 'OTP sent'})
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        


class ValidateOTP(APIView):

    def post(self, request:Request, *args, **kwargs):

        serializer = user_serializer.ValidateOTPSerializer(data=request.data)

        if serializer.is_valid():

            email = serializer.data.get("email")

            otp_klass = fetchone(OTP, user_id=fetchone(User, email=email))

            if otp_klass is None:
                return Response({"message": "User did not request otp"}, status=status.HTTP_400_BAD_REQUEST)

            if not check_password(serializer.data.get("otp"), otp_klass.otp):

                return Response({"message":"Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)


            return Response({"message": "OTP Verified", "data": otp_klass.key})
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class UpdatePasswordFromReset(APIView):
    def put(self, request:Request, *args, **kwargs):
        serializer = user_serializer.UpadatePasswordFromResetSerializer(data=request.data)

        if serializer.is_valid():
            otp_klass = fetchone(OTP, key=serializer.data.get("token"))

            if otp_klass is None:
                return Response({"message": "Invalid Token"}, status=status.HTTP_400_BAD_REQUEST)

            user:User = otp_klass.user

            user.set_password(serializer.data.get("new_password"))

            user.save()

            otp_klass.delete()

            return Response({"message": "Password Changed"})
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)







class PaymentWithCard(APIView):
    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request:Request, *args, **kwargs):


        serializer = user_serializer.PaymentWithCardSerializer(data=request.data)

        if serializer.is_valid():
            try:

                amount = int(serializer.data.get("amount") * 100)

                card_number = str(serializer.data.get("card_number"))

                card_exp_month = str(serializer.data.get("card_exp_month"))

                card_exp_year = str(serializer.data.get("card_exp_year"))

                card_cvc = str(serializer.data.get("card_cvc"))

                currency = str(serializer.data.get("currency"))

                email = str(request.user.email)


                payment_method = stripe.PaymentMethod.create(
                    type='card',
                    card={
                        'number': card_number,
                        'exp_month': card_exp_month,
                        'exp_year': card_exp_year,
                        'cvc': card_cvc
                    }
                )

                customer = stripe.Customer.create(email=email)


                stripe.PaymentMethod.attach(payment_method.id, customer=customer.id)


                stripe.Customer.modify(
                    customer.id,
                    invoice_settings={
                        'default_payment_method': payment_method.id
                    }
                )

                customer.save()


                payment_intent = stripe.PaymentIntent.create(
                    amount= amount,
                    currency=currency,
                    payment_method_types=['card'],
                    payment_method=payment_method.id,
                    customer=customer.id
                )

                payment_intent.confirm()


                return Response({"message" : "Payment successfull", "data": payment_intent}, status=status.HTTP_200_OK)
            
            except stripe.error.CardError as e:

                return Response({"message" : str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
            except stripe.error.StripeError as e:
                return Response({"message" : str(e)}, status=status.HTTP_400_BAD_REQUEST)

            except Exception as e:
                return Response({"message" : str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class PaymentWebHook(APIView):

    @csrf_exempt
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


    def post(self, request:Request, *args, **kwargs):

        payload = request.body

        endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

        sig_header = request.headers.get("stripe-signature")

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, endpoint_secret, tolerance=500000
            )

            if event.type == "charge.succeeded":
                
                _object  = request.data.get("data").get("object")
                
                customer_id = _object.get("customer")

                amount = int(_object.get("amount")) / 100

                currency = _object.get("currency")

                conversion_rate = get_conversion_rate("GBP", str(currency).upper())

                _converted_pounds = amount / conversion_rate

                user_twgos = _converted_pounds / 20

                customer = stripe.Customer.retrieve(customer_id)


                user = fetchone(User, email=customer.email)


                fund_model = fetchone(Funds, user_id=user.id)

                print(fund_model.user)

                if fund_model is  None:
                    new_fund = Funds(user=user, total_balance = round(user_twgos))

                    new_fund.save()

                else:
                    fund_model.total_balance = fund_model.total_balance + Decimal(round(user_twgos, 2))

                    fund_model.save()

            return Response({"message" : "Payment COnfirmed"}, status=status.HTTP_200_OK)
        
        except ValueError as e:

            print(str(e))
            
            return Response({"message" : str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        except stripe.error.SignatureVerificationError as e:
            print(str(e))


            return Response({"message" : str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            print(str(e))


            return Response({"message" : str(e)}, status=status.HTTP_400_BAD_REQUEST)

        

class UpdateDeliveryDate(APIView):

    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def put(self, request:Request, project_id, *args, **kwargs):

        serializer = user_serializer.UpdateDeliveryDateSerializer(data=request.data)

        if serializer.is_valid():

        
            project:Project = fetchone(Project, id=project_id)

            if project is None:
                return Response({"message" : "Project Not Found"}, status=status.HTTP_404_NOT_FOUND)
            
            if project.user != request.user:

                return Response({"message" : "User does not have right to this project"}, status=status.HTTP_403_FORBIDDEN)
            
            project.delivery_date = serializer.data.get("new_delivery_date")

            project.save()

            return Response({"message": "Project Delivery Date Updated"}, status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from datetime import datetime, timedelta
from django.utils import timezone

class SuperUserStats(APIView):

    authentication_classes = (authentication.CustomUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request:Request, *args, **kwargs):
       
       if not request.user.is_superuser:
            
            return Response({"message": "Only super admins are allowed to access Route"}, status.HTTP_403_FORBIDDEN)
       
       stats = {}
       

       threshold = timezone.now() - timedelta(hours=24)

       number_of_users_in_last_24 = fetch_filter(User, date_joined__gte=threshold)

       total_number_users = fetch_filter(User)

       total_number_active_users = fetch_filter(User, is_active=True)


       stats["number_of_users_in_last_24"] = number_of_users_in_last_24.count()

       stats["number_of_new_users"] = number_of_users_in_last_24.count()

       stats["total_number_users"] = total_number_users.count()
       
       stats["total_number_active_users"] = total_number_active_users.count()
       
           

       return Response({"message": "Get Stats Successfully", "data":stats}, status.HTTP_200_OK)

