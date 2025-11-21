# ai_assistant/serializers.py
from rest_framework import serializers
from django.utils import timezone
from .models import AIConversation, AIMessage


class AIChatRequestSerializer(serializers.Serializer):
    mode = serializers.ChoiceField(choices=["budget", "transactions", "notifications", "general"], required=False, default="general")
    message = serializers.CharField(min_length=1, max_length=4000)
    conversation_id = serializers.UUIDField(required=False, allow_null=True)

    def validate_conversation_id(self, value):
        # allow either None or UUID; the view will ensure ownership
        return value


class AIMessageSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default_timezone=timezone.utc, read_only=True)

    class Meta:
        model = AIMessage
        fields = ("id", "role", "content", "meta", "created_at")
        read_only_fields = fields


class AIMessageCreateSerializer(serializers.ModelSerializer):
    """
    Used when creating a new message in a conversation from the user side.
    Role will default to ROLE_USER unless specified (admins may create assistant messages).
    """
    role = serializers.ChoiceField(
        choices=(
            (AIMessage.ROLE_USER, AIMessage.ROLE_USER),
            (AIMessage.ROLE_ASSISTANT, AIMessage.ROLE_ASSISTANT),
            (AIMessage.ROLE_SYSTEM, AIMessage.ROLE_SYSTEM),
        ),
        default=AIMessage.ROLE_USER,
        required=False,
    )

    class Meta:
        model = AIMessage
        fields = ("id", "conversation", "role", "content", "meta")
        read_only_fields = ("id",)


class AIMessageUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = AIMessage
        fields = ("content", "meta")


class AIConversationListSerializer(serializers.ModelSerializer):
    last_message = serializers.SerializerMethodField()
    message_count = serializers.SerializerMethodField()
    updated_at = serializers.DateTimeField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = AIConversation
        fields = (
            "id",
            "title",
            "mode",
            "created_at",
            "updated_at",
            "last_message",
            "message_count",
        )
        read_only_fields = fields

    def get_last_message(self, obj):
        last = obj.messages.order_by("-created_at").first()
        if not last:
            return None
        content = last.content or ""
        preview = content if len(content) <= 240 else content[:240] + "…"
        return {
            "id": str(last.id),
            "role": last.role,
            "content": preview,
            "created_at": last.created_at,
        }

    def get_message_count(self, obj):
        return obj.messages.count()


class AIConversationCreateSerializer(serializers.ModelSerializer):
    """
    Creating a conversation: minimal fields from frontend.
    """
    class Meta:
        model = AIConversation
        fields = ("id", "title", "mode")
        read_only_fields = ("id",)


class AIConversationDetailSerializer(serializers.ModelSerializer):
    messages = AIMessageSerializer(many=True, read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = AIConversation
        fields = (
            "id",
            "title",
            "mode",
            "created_at",
            "updated_at",
            "messages",
        )
        read_only_fields = fields


class AIConversationUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = AIConversation
        fields = ("title", "mode")
