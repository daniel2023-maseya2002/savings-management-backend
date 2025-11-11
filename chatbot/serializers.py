# chatbot/serializers.py
from rest_framework import serializers
from .models import Conversation

class ConversationSerializer(serializers.ModelSerializer):
    user = serializers.SlugRelatedField(
        read_only=True,
        slug_field="username"
    )

    class Meta:
        model = Conversation
        fields = ["id", "user", "user_message", "bot_reply", "created_at"]
        read_only_fields = ["id", "user", "bot_reply", "created_at"]
