# ai_assistant/services.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional, Any, List, Tuple, Iterator, Callable
import logging
import time
import re

from django.conf import settings
from django.contrib.auth import get_user_model

# Try to import ollama; fall back gracefully if not present
try:
    import ollama  # type: ignore
except Exception:  # pragma: no cover
    ollama = None  # type: ignore

from .models import AIConversation, AIMessage

logger = logging.getLogger(__name__)

User = get_user_model()
AIMode = Literal["budget", "transactions", "notifications", "general", "analytics"]


@dataclass
class AIResponse:
    """Returned structure from ask_ai_assistant (non-stream)."""
    mode: AIMode
    reply: str
    used_model: str
    raw: Any
    conversation: Optional[AIConversation]


# ---------- small helpers / settings ----------
def _get_model_name() -> str:
    return getattr(settings, "OLLAMA_MODEL_NAME", "llama3")


def _history_window() -> int:
    return int(getattr(settings, "AI_ASSISTANT_HISTORY_WINDOW", 30))


def _ollama_timeout() -> int:
    return int(getattr(settings, "AI_ASSISTANT_OLLAMA_TIMEOUT", 20))


# ---------- user/context building ----------
def _build_user_context(user: User) -> str:
    lines: List[str] = []

    # 1) Balance
    try:
        balance = getattr(user, "balance", None)
        if balance is not None:
            lines.append(f"- Current wallet balance: {balance} USD")
    except Exception as e:
        logger.debug("Failed to read user.balance: %s", e)

    # 2) Recent transactions (best-effort)
    try:
        from core.models import Transaction  # type: ignore

        recent_tx = Transaction.objects.filter(user=user).order_by("-created_at")[:10]
        if recent_tx:
            lines.append("- Last transactions (most recent first):")
            for t in recent_tx:
                tx_type = getattr(t, "tx_type", "unknown")
                amount = getattr(t, "amount", 0)
                created_at = getattr(t, "created_at", None)
                ts = created_at.isoformat() if created_at else "unknown_time"
                # Note: Transaction model doesn't have status or currency field
                lines.append(f"  • [{ts}] {tx_type} ${amount}")
    except Exception:
        # skip if no Transaction model or error
        pass

    # 3) Unread / urgent notifications (best-effort)
    try:
        from notifications.models import Notification  # type: ignore

        unread = Notification.objects.filter(user=user, read=False).order_by("-created_at")[:10]
        if unread:
            lines.append("- Unread notifications (max 10):")
            for n in unread:
                title = getattr(n, "title", "(no title)")
                body = getattr(n, "body", "") or getattr(n, "message", "")
                created_at = getattr(n, "created_at", None)
                ts = created_at.isoformat() if created_at else "unknown_time"

                priority = getattr(n, "priority", "") or getattr(n, "severity", "")
                is_urgent = False
                if isinstance(priority, str) and priority.lower() in {"high", "urgent"}:
                    is_urgent = True
                if isinstance(title, str) and "urgent" in title.lower():
                    is_urgent = True

                urgent_tag = " (URGENT)" if is_urgent else ""
                short_body = (body[:120] + "…") if body and len(body) > 120 else (body or "")
                lines.append(f"  • [{ts}]{urgent_tag} {title} — {short_body}".strip())
    except Exception:
        pass

    if not lines:
        return "No extra data is available for this user."

    return "\n".join(lines)


# ---------- system prompt ----------
def _build_system_prompt(mode: AIMode) -> str:
    base = (
        "You are the SavingDM AI Assistant.\n"
        "Core responsibilities:\n"
        "1) Help the user manage their budget (spending limits, savings strategy, remaining balance).\n"
        "2) Help the user analyze transactions (what they spent, patterns, whether a new transfer is safe).\n"
        "3) Help the user read and prioritize IMPORTANT and URGENT notifications.\n"
        "\n"
        "General rules:\n"
        "- Be concise, friendly, and practical.\n"
        "- Use bullet points for steps and recommendations.\n"
        "- Never invent balances, transaction IDs or notifications; only use the provided context.\n"
        "- If necessary context is missing, explicitly ask the user for it.\n"
    )

    if mode == "budget":
        extra = (
            "\nMode: BUDGET\n"
            "Focus on budgeting: explain how much the user can safely send, and how a transaction will affect their future balance.\n"
        )
    elif mode == "transactions":
        extra = (
            "\nMode: TRANSACTIONS\n"
            "Focus on explaining past transactions, spending patterns, and the impact of potential new transfers.\n"
        )
    elif mode == "notifications":
        extra = (
            "\nMode: NOTIFICATIONS\n"
            "Focus on summarizing and ranking the most important and urgent notifications. Tell the user what to do first and why.\n"
        )
    elif mode == "analytics":
        extra = (
            "\nMode: ANALYTICS\n"
            "Focus on providing analytical insights, reports, and data-driven recommendations based on transaction patterns and user behavior.\n"
        )
    else:
        extra = (
            "\nMode: GENERAL\n"
            "You may combine budget help, transaction analysis, and notification triage as appropriate.\n"
        )

    return base + extra


# ---------- helpers to extract text from various Ollama responses ----------
def _extract_text_from_result(result: Any) -> str:
    """
    Try many fallbacks to obtain assistant content:
      - dict {"message": {"content": "..."}}
      - dict {"content": "..."} or {"choices":[...]}
      - object with .message and .message.content
      - object with .content
      - plain string
      - last-resort: regex extraction from repr that contains message=Message(... content="...")
    """
    # 1) dict cases
    if isinstance(result, dict):
        # msg as dict under 'message'
        msg = result.get("message")
        if isinstance(msg, dict):
            content = msg.get("content")
            if content:
                return content

        # direct content
        if "content" in result and isinstance(result["content"], str):
            return result["content"]

        # some clients use 'choices' list
        choices = result.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                # openai-like
                text = first.get("text") or (first.get("message") or {}).get("content")
                if text:
                    return text
                # try nested delta
                if "delta" in first and isinstance(first["delta"], dict):
                    return first["delta"].get("content") or first["delta"].get("text") or str(first)

        # if message is object-like (non-dict)
        if msg is not None:
            # try attributes
            content = getattr(msg, "content", None)
            if content:
                return content

    # 2) object with .message attribute
    if hasattr(result, "message"):
        msg = getattr(result, "message")
        # msg might be dict-like
        if isinstance(msg, dict):
            content = msg.get("content")
            if content:
                return content
        # or object
        content = getattr(msg, "content", None)
        if content:
            return content
        # sometimes .message is a list/other
        try:
            return str(msg)
        except Exception:
            pass

    # 3) object with .content attribute
    if hasattr(result, "content"):
        content = getattr(result, "content")
        if content:
            return content

    # 4) string fallback
    if isinstance(result, str):
        # Attempt to extract embedded content if the string is a repr
        s = result
        # quick heuristic: if it contains "message=Message" and "content="
        if "message=Message" in s and "content=" in s:
            extracted = _extract_content_from_repr(s)
            if extracted:
                return extracted
        return s

    # 5) last-resort str()
    try:
        s = str(result)
        if "message=Message" in s and "content=" in s:
            extracted = _extract_content_from_repr(s)
            if extracted:
                return extracted
        return s
    except Exception:
        return ""


def _extract_content_from_repr(s: str) -> Optional[str]:
    """
    Try to extract content="..." or content='...' from a repr string.
    Uses non-greedy DOTALL match to get the inner content; returns unescaped substring if possible.
    """
    try:
        # look for content="..."/content='...'
        m = re.search(r"content=(?:\"|')(?P<c>.*?)(?:\"|')", s, flags=re.DOTALL)
        if m:
            raw = m.group("c")
            # raw may contain escaped sequences; attempt basic unescape of \" and \'
            raw = raw.replace(r'\"', '"').replace(r"\'", "'").replace("\\n", "\n")
            return raw
    except Exception:
        pass
    return None


# ---------- fallback simple responder ----------
def _fallback_reply_for_mode(mode: AIMode, conversation: Optional[AIConversation], message: str) -> AIResponse:
    used_model = "mock-local-v1"
    reply = ""
    raw = {"fallback": True, "mode": mode}

    if mode == "budget":
        total = 0.0
        count = 0
        if conversation:
            for m in conversation.messages.order_by("-created_at")[:_history_window()]:
                for token in (m.content or "").replace(",", " ").split():
                    try:
                        v = float(token)
                        total += v
                        count += 1
                    except Exception:
                        pass
        reply = (
            f"Budget assistant (mock): I found {count} numeric entries in recent messages totalling {total:.2f}.\n"
            "- Suggestion: try the 50/30/20 rule (50% needs, 30% wants, 20% savings).\n"
            "- If you want a specific plan, share your monthly income and recurring expenses."
        )

    elif mode == "transactions":
        total = 0.0
        count = 0
        if conversation:
            for m in conversation.messages.order_by("-created_at")[:_history_window()]:
                for token in (m.content or "").replace(",", " ").split():
                    try:
                        v = float(token)
                        total += v
                        count += 1
                    except Exception:
                        pass
        reply = (
            f"Transaction helper (mock): I analyzed recent messages and found {count} numeric entries totalling {total:.2f}.\n"
            "I can categorize transactions as income/expense if you provide structured data or CSV."
        )

    elif mode == "notifications":
        urgent = []
        regular = []
        if conversation:
            for m in conversation.messages.order_by("-created_at")[:_history_window()]:
                text = (m.content or "").lower()
                if any(k in text for k in ("urgent", "due", "overdue", "pay now", "immediately")):
                    urgent.append(m.content)
                else:
                    regular.append(m.content)
        if urgent:
            reply = "Important notifications (mock):\n- " + "\n- ".join(urgent[:5])
        else:
            reply = "No urgent notifications were found in recent conversation history. Provide your notifications and I'll prioritize them."

    elif mode == "analytics":
        reply = (
            "Analytics assistant (mock): I can help you analyze system-wide data, user performance, and transaction patterns.\n"
            "Please provide specific queries about metrics, trends, or reports you'd like to see."
        )

    else:
        reply = (
            "Hello — I'm the SavingDM assistant (mock). I can help with budgeting, transaction analysis, "
            "and notification triage. Try: 'Analyze my last 10 transactions' or 'Highlight urgent notifications'."
        )

    return AIResponse(mode=mode, reply=reply, used_model=used_model, raw=raw, conversation=conversation)


# ---------- streaming generator normalization ----------
def _normalize_stream_item(item: Any) -> str:
    """
    Given one item yielded by the ollama streaming client, return a textual chunk.
    Handles dicts, objects with .content, and plain strings.
    """
    # If dict with 'content' or 'message'
    if isinstance(item, dict):
        if "content" in item and isinstance(item["content"], str):
            return item["content"]
        if "message" in item:
            msg = item["message"]
            if isinstance(msg, dict) and "content" in msg:
                return msg["content"]
            # object-like
            try:
                return str(getattr(msg, "content", msg))
            except Exception:
                return str(msg)
        # fallback: stringify
        return str(item)

    # object with .content or .message
    if hasattr(item, "content"):
        return str(getattr(item, "content") or "")
    if hasattr(item, "message"):
        msg = getattr(item, "message")
        if isinstance(msg, dict) and "content" in msg:
            return msg["content"]
        if hasattr(msg, "content"):
            return str(getattr(msg, "content") or "")
        return str(msg)

    # plain string
    return str(item)


# ---------- main entry (non-streaming and streaming) ----------
def ask_ai_assistant(
    *,
    user: User,
    message: str,
    mode: Optional[AIMode] = "general",
    conversation: Optional[AIConversation] = None,
    stream: bool = False,
) -> Any:
    """
    Ask the AI assistant.

    - If stream=False: returns AIResponse (non-persistent).
    - If stream=True: returns (generator, finalizer) where:
         generator -> yields textual chunks (str)
         finalizer -> callable() -> AIResponse (final aggregated response)
    """
    if mode not in ("budget", "transactions", "notifications", "general", "analytics"):
        mode = "general"

    if conversation is not None and getattr(conversation, "mode", None):
        mode = conversation.mode

    user_context = _build_user_context(user)
    system_prompt = _build_system_prompt(mode)
    model_name = _get_model_name()

    messages: List[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "system", "content": "User context:\n" + user_context},
    ]

    # attach conversation history (oldest -> newest)
    if conversation is not None:
        window = _history_window()
        qs = conversation.messages.order_by("-created_at")[:window]
        recent_messages = list(qs)[::-1]
        for m in recent_messages:
            role = m.role if m.role in {"user", "assistant", "system"} else "user"
            messages.append({"role": role, "content": m.content or ""})

    # append the current user message
    messages.append({"role": "user", "content": message})

    use_ollama = bool(getattr(settings, "AI_ASSISTANT_USE_OLLAMA", True))
    if use_ollama and ollama is not None:
        # Non-streaming path
        if not stream:
            try:
                timeout = _ollama_timeout()
                start = time.time()
                # Many versions of the ollama client accept (model, messages) only.
                # We attempt to pass timeout as kwargs but swallow errors if client doesn't accept it.
                try:
                    raw_result = ollama.chat(model=model_name, messages=messages, timeout=timeout)  # type: ignore
                except TypeError:
                    # some clients do not accept timeout kwarg
                    raw_result = ollama.chat(model=model_name, messages=messages)  # type: ignore
                took = time.time() - start
                logger.debug("Ollama chat succeeded in %.2fs (model=%s)", took, model_name)

                reply_text = _extract_text_from_result(raw_result)
                used_model = getattr(raw_result, "model", model_name) or model_name
                # If used_model is inside dict
                if isinstance(raw_result, dict) and not getattr(raw_result, "model", None):
                    used_model = raw_result.get("model") or used_model

                return AIResponse(mode=mode, reply=reply_text, used_model=used_model, raw=raw_result, conversation=conversation)

            except Exception as e:
                logger.exception("Ollama call failed or not configured properly: %s", e)
                # fall through to fallback

        # Streaming path
        else:
            try:
                # try to request streaming; different client versions accept different args
                try:
                    stream_iter = ollama.chat(model=model_name, messages=messages, stream=True)  # type: ignore
                except TypeError:
                    # maybe client expects stream parameter inside data
                    stream_iter = ollama.chat(model=model_name, messages=messages, stream=True)  # try again or will raise

                # stream_iter might be generator of strings/dicts/objects
                def gen() -> Iterator[str]:
                    try:
                        for item in stream_iter:
                            chunk = _normalize_stream_item(item)
                            if chunk:
                                yield chunk
                    except Exception as e:
                        logger.exception("Error iterating ollama stream: %s", e)
                        # Raise or stop iteration; generator consumers should handle ends
                        return

                # finalizer: attempt to obtain last full result if client provides it,
                # otherwise re-run a non-stream call to get final output (safe fallback).
                def finalizer() -> AIResponse:
                    # If the streaming iterator produced a "final" value or the client gives access to final result,
                    # we try to extract it. Otherwise, perform a non-stream chat call quickly.
                    try:
                        # some clients return an object with .final or similar; try to inspect
                        if hasattr(stream_iter, "final"):
                            raw_final = getattr(stream_iter, "final")
                            reply_text = _extract_text_from_result(raw_final)
                            used_model = getattr(raw_final, "model", model_name) or model_name
                            return AIResponse(mode=mode, reply=reply_text, used_model=used_model, raw=raw_final, conversation=conversation)
                    except Exception:
                        logger.debug("No final object on stream iterator.")

                    # fallback: run a non-stream call to get the final response
                    try:
                        try:
                            raw_result = ollama.chat(model=model_name, messages=messages)  # type: ignore
                        except TypeError:
                            raw_result = ollama.chat(model=model_name, messages=messages)  # attempt again
                        reply_text = _extract_text_from_result(raw_result)
                        used_model = getattr(raw_result, "model", model_name) or model_name
                        return AIResponse(mode=mode, reply=reply_text, used_model=used_model, raw=raw_result, conversation=conversation)
                    except Exception as e:
                        logger.exception("Failed to fetch final result after streaming: %s", e)
                        # return fallback mock
                        return _fallback_reply_for_mode(mode, conversation, message)

                return gen(), finalizer

            except Exception as e:
                logger.exception("Ollama streaming failed: %s", e)
                # fall through to fallback

    # Ollama disabled or not installed, or call failed -> fallback mock responder
    logger.debug("Using fallback mock responder for AI assistant (mode=%s)", mode)
    return _fallback_reply_for_mode(mode, conversation, message)