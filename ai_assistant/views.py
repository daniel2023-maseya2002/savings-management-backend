# D:\Downloads\JuniorDeveloper\CreditJambo\ai_assistant\views.py
import json
import time
import logging
from typing import Iterator, Optional

from django.shortcuts import get_object_or_404
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.exceptions import PermissionDenied, ValidationError
from django.http import StreamingHttpResponse, HttpResponse, JsonResponse

# SimpleJWT authentication helper
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import AIConversation, AIMessage
from .serializers import (
    AIChatRequestSerializer,
    AIConversationListSerializer,
    AIConversationCreateSerializer,
    AIConversationDetailSerializer,
    AIConversationUpdateSerializer,
    AIMessageSerializer,
    AIMessageCreateSerializer,
    AIMessageUpdateSerializer,
)
from .services import ask_ai_assistant
from django.views.decorators.csrf import csrf_exempt
from django.utils.encoding import force_str

logger = logging.getLogger(__name__)


class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 200


# -------------------------
# Helper function to check conversation access
# -------------------------
def check_conversation_access(user, conversation, allow_staff=True):
    """
    Check if user has access to a conversation.
    Returns True if access is granted, raises PermissionDenied otherwise.
    
    Args:
        user: The requesting user
        conversation: The AIConversation object
        allow_staff: Whether to allow staff/admin access (default True)
    """
    if conversation.user_id == user.id:
        return True
    if allow_staff and user.is_staff:
        return True
    raise PermissionDenied("You do not have permission to access this conversation.")


# -------------------------
# Conversations CRUD
# -------------------------
class ConversationListView(generics.ListCreateAPIView):
    """
    List conversations for the current user, or all conversations for admin users.
    Create a new conversation.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AIConversationListSerializer
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        # Admin users can see all conversations, regular users only their own
        if self.request.user.is_staff:
            return AIConversation.objects.all().order_by("-updated_at")
        return AIConversation.objects.filter(user=self.request.user).order_by("-updated_at")

    def get_serializer_class(self):
        if self.request.method == "POST":
            return AIConversationCreateSerializer
        return AIConversationListSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        out_serializer = AIConversationListSerializer(serializer.instance, context={"request": request})
        headers = self.get_success_headers(out_serializer.data)
        return Response(out_serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class ConversationCreateView(generics.CreateAPIView):
    """Create a new conversation."""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AIConversationCreateSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class ConversationDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update, or delete a conversation.
    Users can only access their own conversations, admins can access all.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    queryset = AIConversation.objects.all()
    lookup_field = "id"
    serializer_class = AIConversationDetailSerializer

    def get_serializer_class(self):
        if self.request.method in ("PATCH", "PUT"):
            return AIConversationUpdateSerializer
        return AIConversationDetailSerializer

    def check_object_permissions(self, request, obj):
        check_conversation_access(request.user, obj, allow_staff=True)
        return super().check_object_permissions(request, obj)


# -------------------------
# Messages CRUD
# -------------------------
class MessageListView(generics.ListAPIView):
    """List messages for a specific conversation."""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AIMessageSerializer
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        conv_id = self.kwargs.get("conversation_id")
        conv = get_object_or_404(AIConversation, id=conv_id)
        check_conversation_access(self.request.user, conv, allow_staff=True)
        return conv.messages.order_by("created_at")


class MessageCreateView(generics.CreateAPIView):
    """Create a new message in a conversation."""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AIMessageCreateSerializer

    def perform_create(self, serializer):
        conv_id = serializer.validated_data.get("conversation") or self.request.data.get("conversation")
        if not conv_id:
            raise ValidationError({"conversation": "This field is required."})
        conversation = get_object_or_404(AIConversation, id=conv_id)
        check_conversation_access(self.request.user, conversation, allow_staff=True)
        serializer.save()


class MessageDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a specific message."""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AIMessageSerializer
    queryset = AIMessage.objects.all()
    lookup_field = "id"

    def get_serializer_class(self):
        if self.request.method in ("PATCH", "PUT"):
            return AIMessageUpdateSerializer
        return AIMessageSerializer

    def check_object_permissions(self, request, obj):
        conv = obj.conversation
        check_conversation_access(request.user, conv, allow_staff=True)
        return super().check_object_permissions(request, obj)


# -------------------------
# Conversation retrieve with paginated messages
# -------------------------
class ConversationRetrieveView(APIView):
    """
    Retrieve a conversation with its messages.
    Supports pagination for messages.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get(self, request, id, *args, **kwargs):
        conv = get_object_or_404(AIConversation, id=id)
        check_conversation_access(request.user, conv, allow_staff=True)

        conv_ser = AIConversationListSerializer(conv, context={"request": request})
        messages_qs = conv.messages.order_by("created_at")
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(messages_qs, request, view=self)
        messages_ser = AIMessageSerializer(page, many=True, context={"request": request})

        payload = {
            "conversation": conv_ser.data,
            "messages": messages_ser.data,
        }
        return paginator.get_paginated_response(payload)


# -------------------------
# AI chat endpoint (non-streaming)
# -------------------------
class AIChatView(APIView):
    """
    Non-streaming AI chat endpoint.
    Send a message and get a complete response.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = AIChatRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        mode = serializer.validated_data.get("mode", "general")
        message = serializer.validated_data["message"]
        conversation_id = serializer.validated_data.get("conversation_id")

        conversation = None
        if conversation_id:
            conversation = get_object_or_404(AIConversation, id=conversation_id)
            check_conversation_access(request.user, conversation, allow_staff=True)

        try:
            ai_response = ask_ai_assistant(
                user=request.user,
                message=message,
                mode=mode,
                conversation=conversation,
                stream=False,
            )

            response_data = {
                "reply": ai_response.reply,
                "model": ai_response.used_model,
                "conversation_id": str(conversation.id) if conversation else None,
            }
            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception("AIChatView error")
            return Response(
                {"error": "AI service error", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# -------------------------
# SSE helper
# -------------------------
def sse_format(event_type: str, data: dict) -> str:
    """
    Format data as a Server-Sent Event frame.
    
    Args:
        event_type: The event type (e.g., 'chunk', 'done', 'error', 'meta')
        data: Dictionary to be JSON-encoded
    
    Returns:
        Formatted SSE string
    """
    payload = {"type": event_type, **data}
    return f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"


def dummy_ai_stream_generator(message: str, conversation_id: Optional[str], mode: str):
    """
    Fallback dummy generator for testing SSE streaming.
    Yields fake chunks to simulate AI response.
    """
    chunks = [f"Received: '{message}' ", f"(mode={mode}, ", f"conversation={conversation_id})"]
    for chunk in chunks:
        yield sse_format("chunk", {"text": chunk})
        time.sleep(0.05)
    yield sse_format("done", {"text": f"Final response for '{message}'", "model": "llama2:latest"})


@csrf_exempt
def assistant_stream(request):
    """
    Function-based SSE streaming endpoint that:
      - Accepts POST (EventSourcePolyfill) with JSON body or GET with query params
      - Supports Authorization: Bearer <token> via JWTAuthentication
      - Returns text/event-stream with appropriate CORS headers
      - Uses ask_ai_assistant(..., stream=True) if available, otherwise falls back to dummy generator
      - Persists user messages immediately and assistant messages after streaming completes
    """
    # Handle preflight OPTIONS request
    if request.method == "OPTIONS":
        resp = HttpResponse()
        resp["Access-Control-Allow-Origin"] = "*"  # Tighten for production
        resp["Access-Control-Allow-Methods"] = "POST,GET,OPTIONS"
        resp["Access-Control-Allow-Headers"] = "Authorization,Content-Type,Accept"
        resp["Access-Control-Max-Age"] = "3600"
        return resp

    logger.debug("assistant_stream called method=%s", request.method)

    # Authenticate using SimpleJWT
    user = None
    validated_token = None
    try:
        auth = JWTAuthentication()
        auth_result = auth.authenticate(request)  # returns (user, validated_token) or None
        if auth_result:
            user, validated_token = auth_result
            logger.debug("assistant_stream auth success user_id=%s is_staff=%s", 
                        getattr(user, "id", None), getattr(user, "is_staff", False))
        else:
            logger.warning("assistant_stream: no valid credentials provided")
            return JsonResponse({"detail": "Authentication credentials were not provided"}, status=401)
    except Exception as e:
        logger.exception("assistant_stream authentication error: %s", e)
        return JsonResponse({"detail": "Invalid token or authentication error"}, status=401)

    # Parse request body or query params
    message = ""
    conversation_id = None
    mode = "general"
    
    if request.method == "POST":
        try:
            body = json.loads(request.body.decode("utf-8") or "{}")
            message = body.get("message", "") or body.get("msg", "")
            conversation_id = body.get("conversation_id") or body.get("conversationId")
            mode = body.get("mode", "general")
            logger.debug("POST body parsed: message_len=%d, conversation_id=%s, mode=%s", 
                        len(message), conversation_id, mode)
        except Exception as e:
            logger.exception("assistant_stream failed to parse JSON body: %s", e)
            message = ""
    else:
        # GET request
        message = request.GET.get("message", "") or request.GET.get("msg", "")
        conversation_id = request.GET.get("conversation_id")
        mode = request.GET.get("mode", "general")
        logger.debug("GET params: message_len=%d, conversation_id=%s, mode=%s", 
                    len(message), conversation_id, mode)

    # Validate message
    if not message:
        def empty_gen():
            yield sse_format("error", {"message": "Missing 'message' in request"})
        
        response = StreamingHttpResponse(empty_gen(), content_type="text/event-stream")
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Headers"] = "Authorization,Content-Type,Accept"
        response["Cache-Control"] = "no-cache, no-transform"
        response["X-Accel-Buffering"] = "no"
        return response

    # Resolve conversation object if provided
    conv_obj = None
    if conversation_id:
        try:
            conv_obj = AIConversation.objects.get(id=conversation_id)
            # Check access permissions
            try:
                check_conversation_access(user, conv_obj, allow_staff=True)
                logger.debug("User %s has access to conversation %s", user.id, conversation_id)
            except PermissionDenied as e:
                logger.warning("Permission denied for user %s on conversation %s", user.id, conversation_id)
                def error_gen():
                    yield sse_format("error", {"message": str(e)})
                
                response = StreamingHttpResponse(error_gen(), content_type="text/event-stream")
                response["Access-Control-Allow-Origin"] = "*"
                response["Access-Control-Allow-Headers"] = "Authorization,Content-Type,Accept"
                response["Cache-Control"] = "no-cache, no-transform"
                response["X-Accel-Buffering"] = "no"
                return response
        except AIConversation.DoesNotExist:
            logger.warning("assistant_stream: conversation id %s not found", conversation_id)
            conv_obj = None

    # Persist user message immediately (before streaming)
    if conv_obj:
        try:
            user_msg = AIMessage.objects.create(
                conversation=conv_obj,
                role=AIMessage.ROLE_USER,
                content=message
            )
            logger.debug("Persisted user message id=%s to conversation %s", user_msg.id, conv_obj.id)
        except Exception as e:
            logger.exception("Failed to persist user message: %s", e)

    # Try to get streaming generator from AI service
    gen = None
    finalizer = None
    try:
        maybe = ask_ai_assistant(
            user=user,
            message=message,
            mode=mode,
            conversation=conv_obj,
            stream=True
        )
        
        if isinstance(maybe, tuple) and len(maybe) == 2:
            # Got streaming generator + finalizer
            gen, finalizer = maybe
            logger.debug("Received streaming generator and finalizer from AI service")
        else:
            # Got a non-stream AIResponse - send it as a single done event
            ai_resp = maybe
            logger.debug("Received non-stream response from AI service")
            
            # Persist assistant message
            if conv_obj:
                try:
                    assistant_msg = AIMessage.objects.create(
                        conversation=conv_obj,
                        role=AIMessage.ROLE_ASSISTANT,
                        content=getattr(ai_resp, "reply", "")
                    )
                    logger.debug("Persisted assistant message id=%s", assistant_msg.id)
                except Exception as e:
                    logger.exception("Failed to persist non-stream assistant message: %s", e)
            
            payload = sse_format(
                "done",
                {
                    "text": getattr(ai_resp, "reply", ""),
                    "model": getattr(ai_resp, "used_model", None)
                }
            )
            response = StreamingHttpResponse(iter([payload]), content_type="text/event-stream")
            response["Cache-Control"] = "no-cache, no-transform"
            response["X-Accel-Buffering"] = "no"
            response["Access-Control-Allow-Origin"] = "*"
            response["Access-Control-Allow-Headers"] = "Authorization,Content-Type,Accept"
            return response
            
    except Exception as e:
        logger.exception("ask_ai_assistant threw an exception: %s", e)
        gen = None
        finalizer = None

    # Fallback to dummy generator if AI service failed
    if gen is None:
        logger.warning("Using dummy generator as fallback")
        gen = dummy_ai_stream_generator(message, conversation_id, mode)
        finalizer = None

    # Stream wrapper function
    def event_stream() -> Iterator[str]:
        """Generator that yields SSE-formatted events."""
        last_heartbeat = time.time()
        accumulated_text = []  # Accumulate chunks for final persistence
        
        # Send meta event with conversation info
        try:
            meta = {
                "type": "meta",
                "conversation_id": str(conversation_id) if conversation_id else None,
                "user_id": str(user.id) if user else None,
                "mode": mode
            }
            yield sse_format("meta", meta)
        except Exception as e:
            logger.exception("Error sending meta event: %s", e)

        try:
            # Stream chunks from generator
            for raw_chunk in gen:
                if raw_chunk is None:
                    continue

                # If already formatted SSE frame, yield directly
                if isinstance(raw_chunk, str) and raw_chunk.strip().startswith("data:"):
                    yield raw_chunk
                    # Try to extract text for accumulation
                    try:
                        data_line = [line for line in raw_chunk.split("\n") if line.startswith("data:")][0]
                        data_json = json.loads(data_line[5:].strip())
                        if "text" in data_json:
                            accumulated_text.append(data_json["text"])
                    except:
                        pass
                else:
                    # Format and send chunk
                    if isinstance(raw_chunk, (dict, list)):
                        text = json.dumps(raw_chunk, separators=(",", ":"))
                    else:
                        text = str(raw_chunk)
                    
                    accumulated_text.append(text)
                    yield sse_format("chunk", {"text": text})

                # Send periodic heartbeat
                now = time.time()
                if now - last_heartbeat > 15.0:
                    try:
                        yield ": keep-alive\n\n"
                    except GeneratorExit:
                        logger.info("SSE client disconnected during heartbeat")
                        return
                    last_heartbeat = now

            # Call finalizer if present
            final_resp = None
            if callable(finalizer):
                try:
                    final_resp = finalizer()
                    logger.debug("Finalizer executed successfully")
                except Exception as e:
                    logger.exception("Finalizer failed: %s", e)
                    yield sse_format("error", {"message": "AI finalization failed"})
                    return

            # Determine final text
            final_text = ""
            final_model = None
            
            if final_resp is not None:
                final_text = getattr(final_resp, "reply", "")
                final_model = getattr(final_resp, "used_model", None)
            else:
                # Use accumulated text if no finalizer response
                final_text = "".join(accumulated_text)

            # Persist assistant message
            if conv_obj and final_text:
                try:
                    assistant_msg = AIMessage.objects.create(
                        conversation=conv_obj,
                        role=AIMessage.ROLE_ASSISTANT,
                        content=final_text
                    )
                    logger.debug("Persisted streamed assistant message id=%s with %d chars", 
                                assistant_msg.id, len(final_text))
                except Exception as e:
                    logger.exception("Error persisting assistant message: %s", e)

            # Send done event
            done_payload = {
                "type": "done",
                "text": final_text,
                "model": final_model
            }
            yield sse_format("done", done_payload)
            logger.debug("Stream completed successfully")

        except GeneratorExit:
            logger.info("SSE client disconnected (GeneratorExit)")
            return
        except Exception as e:
            logger.exception("Unexpected error in SSE event_stream: %s", e)
            yield sse_format("error", {"message": "AI streaming error"})
            return

    # Create streaming response
    response = StreamingHttpResponse(event_stream(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache, no-transform"
    response["X-Accel-Buffering"] = "no"
    response["Access-Control-Allow-Origin"] = "*"
    response["Access-Control-Allow-Headers"] = "Authorization,Content-Type,Accept"
    
    return response