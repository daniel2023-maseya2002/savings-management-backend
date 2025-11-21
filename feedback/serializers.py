# feedback/serializers.py
from rest_framework import serializers
from .models import Feedback, FeedbackComment

class FeedbackCommentSerializer(serializers.ModelSerializer):
    user_display = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = FeedbackComment
        fields = ["id", "feedback", "user", "user_display", "content", "is_internal", "created_at"]
        read_only_fields = ["id", "user", "user_display", "created_at"]

    def get_user_display(self, obj):
        try:
            return getattr(obj.user, "username", str(obj.user))
        except Exception:
            return None

    def validate(self, data):
        # Prevent non-staff from setting is_internal True
        request = self.context.get("request")
        if data.get("is_internal") and not (request and request.user and request.user.is_staff):
            raise serializers.ValidationError({"is_internal": "Only staff can add internal comments."})
        return data


class FeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feedback
        fields = ["id", "user", "title", "message", "rating", "is_public", "status", "created_at", "updated_at"]
        read_only_fields = ["id", "user", "created_at", "updated_at"]

    def create(self, validated_data):
        request = self.context.get("request")
        # Force user
        if request and request.user and request.user.is_authenticated:
            validated_data["user"] = request.user

        # if non-staff tried to set status, ignore it (force default)
        if not (request and getattr(request.user, "is_staff", False)):
            validated_data.pop("status", None)  # ensure default 'in_progress' is used

        return super().create(validated_data)

    def update(self, instance, validated_data):
        # allow admins to change status; regular users should NOT update status
        request = self.context.get("request")
        if not (request and getattr(request.user, "is_staff", False)):
            validated_data.pop("status", None)
        return super().update(instance, validated_data)