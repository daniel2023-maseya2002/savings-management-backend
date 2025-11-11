# chatbot/views.py
import json
import re
import logging
from pathlib import Path

from django.core.paginator import Paginator
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status

from .models import Conversation
from .serializers import ConversationSerializer
from rest_framework.pagination import PageNumberPagination

logger = logging.getLogger(__name__)

BASE = Path(__file__).resolve().parent
QA_FILE = BASE / "qa.json"


def load_qa():
    try:
        raw = []
        if QA_FILE.exists():
            raw = json.loads(QA_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.exception("Failed to load qa.json: %s", exc)
        raw = []

    if not raw:
        raw = [
            {"patterns": ["hi", "hello", "hey"], "reply": "Hello! 👋 How can I help you with savings today?"},
            {"patterns": ["deposit", "how to deposit"], "reply": "To deposit, go to Wallet → Deposit and follow the steps."},
        ]

    prepared = []
    for item in raw:
        patterns = item.get("patterns", []) or []
        compiled = []
        for p in patterns:
            p_norm = p.strip()
            # treat likely regexes as regex; else substring
            # heuristic: if it starts with ^ or contains regex special chars treat as regex
            if p_norm.startswith("^") or any(ch in p_norm for ch in ".*?+[]()\\|"):
                try:
                    compiled.append(("regex", re.compile(p_norm, flags=re.IGNORECASE)))
                except re.error:
                    # fallback to substring when regex is invalid
                    compiled.append(("substr", p_norm.lower()))
            else:
                compiled.append(("substr", p_norm.lower()))
        prepared.append({
            "raw_patterns": patterns,
            "reply": item.get("reply", ""),
            "compiled": compiled,
        })
    return prepared


QA_DATA = load_qa()


# ---------- Helpers for amount / currency normalization ----------
def parse_amount_str(s: str):
    """
    Parse a numeric amount string like "5k", "10,000", "10.5", "2m", "1,200.50" -> float/int.
    Returns a string nicely formatted (no trailing .0 if integer) and raw numeric value as float.
    If parsing fails, returns (original_string, None)
    """
    if not s:
        return None, None
    original = s.strip().lower()
    # replace common separators and spaces
    cleaned = original.replace(",", "").replace(" ", "")

    # handle suffixes like k (thousand), m (million)
    m_suffix = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([km])$", cleaned, flags=re.IGNORECASE)
    if m_suffix:
        num = float(m_suffix.group(1))
        suff = m_suffix.group(2).lower()
        if suff == "k":
            val = num * 1_000
        elif suff == "m":
            val = num * 1_000_000
        else:
            val = num
        return format_amount(val), val

    # if it contains only digits or decimal point
    try:
        if re.match(r"^[0-9]+(?:\.[0-9]+)?$", cleaned):
            val = float(cleaned)
            return format_amount(val), val
    except Exception:
        pass

    # fallback: try to extract leading number
    m = re.search(r"([0-9]+(?:[.,][0-9]+)?)", original)
    if m:
        try:
            maybe = m.group(1).replace(",", "")
            val = float(maybe)
            return format_amount(val), val
        except Exception:
            pass

    # could not parse — return original
    return original, None


def format_amount(value):
    """
    Nicely format a numeric amount: drop .0 for integers, add thousand separators
    """
    try:
        if value is None:
            return ""
        # if it's effectively integer
        iv = int(value)
        if abs(value - iv) < 1e-9:
            return f"{iv:,}"
        # else show up to 2 decimal places (strip trailing zeros)
        return f"{value:,.2f}".rstrip("0").rstrip(".")
    except Exception:
        return str(value)


def normalize_currency_token(token: str):
    """
    Normalize some currency tokens to readable forms. Default to 'RWF' if unknown/empty.
    """
    if not token:
        return "RWF"
    t = token.strip().lower()
    if t in ("rwf", "frw"):
        return "RWF"
    if t in ("usd", "dollar", "dollars", "$"):
        return "USD"
    if t in ("k", "thousand", "m", "million"):
        # these are suffixes and better handled in amount parsing; return as-is fallback
        return token.upper()
    return token.upper()


# ---------- Improved find_reply ----------
def find_reply(user_text):
    """
    - substring patterns are matched as before
    - regex patterns (compiled) are matched against the original user_text
    - if regex pattern has named groups and the reply template contains placeholders like {amount},
      those placeholders are filled from the regex named groups (normalized when possible)
    """
    if not user_text:
        return ""
    text = user_text  # keep original for regex matching
    text_lower = user_text.lower()

    for item in QA_DATA:
        for typ, patt in item["compiled"]:
            try:
                if typ == "substr":
                    # patt is lowercase substring
                    if patt in text_lower:
                        return item.get("reply", "")
                elif typ == "regex":
                    # patt is a compiled regex
                    if isinstance(patt, str):
                        # defensive: if patt ended up as string fallback, do substring match
                        if patt.lower() in text_lower:
                            return item.get("reply", "")
                        continue

                    m = patt.search(text)
                    if m:
                        reply_template = item.get("reply", "")
                        gd = m.groupdict()

                        # normalize and prepare formatting context
                        ctx = {}
                        if gd:
                            for k, v in gd.items():
                                if v is None:
                                    ctx[k] = ""
                                    continue
                                # common keys normalization
                                if k.lower() in ("amount", "amt", "value"):
                                    pretty, num = parse_amount_str(v)
                                    ctx[k] = pretty if pretty is not None else v
                                    ctx[f"{k}_num"] = num
                                elif k.lower() in ("currency", "curr"):
                                    ctx[k] = normalize_currency_token(v)
                                else:
                                    # default: trim
                                    ctx[k] = v.strip()

                        # If reply template has placeholders and we have ctx, try formatting
                        if gd and ("{" in reply_template):
                            try:
                                return reply_template.format(**ctx)
                            except Exception:
                                # fallback: try to inject raw groups (without normalization)
                                try:
                                    return reply_template.format(**m.groupdict())
                                except Exception:
                                    # final fallback: return plain template without formatting
                                    return reply_template
                        else:
                            return reply_template
            except re.error:
                # regex error fallback: if patt is a string substring, check it
                try:
                    if isinstance(patt, str) and patt.lower() in text_lower:
                        return item.get("reply", "")
                except Exception:
                    pass
                continue

    # fallback heuristics
    if any(w in text_lower for w in ["thank", "thanks"]):
        return "You're welcome! 😊"
    if "help" in text_lower:
        return "Tell me what you need help with — deposits, withdrawals, or account info."
    return "Sorry, I don't know that yet. Try asking about deposits, withdrawals, or working hours."


# ---------- API views (unchanged behavior) ----------
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def message(request):
    """
    POST JSON: { "message": "Hello" } - Auth required (Bearer token)
    Saves conversation to DB and returns bot reply.
    """
    user = request.user if request and hasattr(request, "user") else None
    user_msg = request.data.get("message", "")
    if user_msg is None:
        return Response({"error": "message field required"}, status=status.HTTP_400_BAD_REQUEST)

    reply = find_reply(user_msg)

    try:
        Conversation.objects.create(
            user=user if user and getattr(user, "is_authenticated", False) else None,
            user_message=user_msg,
            bot_reply=reply
        )
    except Exception:
        logger.exception("Failed to save conversation for user=%s", getattr(user, "pk", None))

    return Response({"reply": reply}, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def history(request):
    """
    GET: returns authenticated user's conversations, paginated.
    Query params:
      - page (int, default=1)
      - page_size (int, default=20)
    """
    user = request.user
    page = int(request.query_params.get("page", 1))
    page_size = int(request.query_params.get("page_size", 20))
    qs = Conversation.objects.filter(user=user).order_by("-created_at")
    paginator = Paginator(qs, page_size)
    try:
        page_obj = paginator.page(page)
    except Exception:
        return Response({"detail": "Invalid page."}, status=status.HTTP_400_BAD_REQUEST)

    serializer = ConversationSerializer(page_obj.object_list, many=True)
    return Response({
        "count": paginator.count,
        "num_pages": paginator.num_pages,
        "page": page,
        "page_size": page_size,
        "results": serializer.data
    }, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAdminUser])
def all_conversations(request):
    """
    Admin-only: return paginated conversations.
    Optional query params:
      - user: username or user id to filter conversations
      - page, page_size
    """
    user_q = request.query_params.get("user", None)
    qs = Conversation.objects.all().order_by("-created_at")

    if user_q:
        try:
            qs = qs.filter(user__id=int(user_q))
        except Exception:
            qs = qs.filter(user__username__icontains=user_q)

    page = int(request.query_params.get("page", 1))
    page_size = int(request.query_params.get("page_size", 20))

    paginator = Paginator(qs, page_size)
    try:
        page_obj = paginator.page(page)
    except Exception:
        return Response({"detail": "Invalid page."}, status=status.HTTP_400_BAD_REQUEST)

    serializer = ConversationSerializer(page_obj.object_list, many=True)
    return Response({
        "count": paginator.count,
        "num_pages": paginator.num_pages,
        "page": page,
        "page_size": page_size,
        "results": serializer.data
    }, status=status.HTTP_200_OK)


class AdminConversationsPagination(PageNumberPagination):
    page_size = 30
    page_size_query_param = "page_size"
    max_page_size = 200


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_list_conversations(request):
    """
    Admin-only: list all conversations (paginated).
    Query params: page, page_size, user (optional filter by user id or username)
    """
    user = request.user
    if not user.is_staff:
        return Response({"detail": "Not authorized."}, status=status.HTTP_403_FORBIDDEN)

    qs = Conversation.objects.all().order_by("-created_at")

    # optional filter by username or id
    user_q = request.query_params.get("user")
    if user_q:
        # try id first
        if user_q.isdigit():
            qs = qs.filter(user__id=int(user_q))
        else:
            qs = qs.filter(user__username__icontains=user_q)

    paginator = AdminConversationsPagination()
    page = paginator.paginate_queryset(qs, request)
    serializer = ConversationSerializer(page, many=True)
    return paginator.get_paginated_response(serializer.data)
