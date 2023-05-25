from rest_framework import serializers

from .models import *

from . import services


class UserSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    email = serializers.CharField()
    password = serializers.CharField(write_only=True)
    phone_number = serializers.CharField()
    nationality = serializers.CharField()
    gender = serializers.CharField()

    def to_internal_value(self, data):
        data = super().to_internal_value(data)
        return services.UserDataClass(**data)


class ProjectSerializer(serializers.ModelSerializer):
    user = serializers.ReadOnlyField(source='user.username')
    admin = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), required=False)

    class Meta:
        model = Project
        fields = '__all__'


class FundsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Funds
        fields = ('total_balance', 'deposit', 'referral_bonus')


class NotificationsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notifications
        fields = ('id', 'user', 'message', 'details', 'is_read', 'created_at')
