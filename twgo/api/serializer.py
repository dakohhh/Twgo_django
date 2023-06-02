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


class ConversationSerializer(serializers.ModelSerializer):
    title = serializers.CharField(
        read_only=True, default="Project Related Chat")
    participants = serializers.SerializerMethodField()

    def get_participants(self, conversation):
        participants_data = []
        participants = conversation.participants.all()

        for participant in participants:
            participant_data = {
                'id': participant.id,
                'name': f"{participant.first_name} {participant.last_name}"
            }
            participants_data.append(participant_data)

        return participants_data

    def create(self, validated_data):
        participants_data = self.initial_data.get('participants', [])
        conversation = Conversation.objects.create()

        for participant_data in participants_data:
            participant_id = participant_data.get('id')
            conversation.participants.add(participant_id)

        return conversation

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['title'] = instance.title
        return representation

    class Meta:
        model = Conversation
        fields = ['id', 'title', 'created_at', 'participants']


class MessageSerializer(serializers.ModelSerializer):
    conversation_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = Message
        fields = ['sender', 'conversation_id', 'content', 'created_at']
        read_only_fields = ['sender', 'created_at']

    def create(self, validated_data):
        conversation_id = validated_data.pop('conversation_id')
        message = Message.objects.create(
            conversation_id=conversation_id, **validated_data)
        return message
