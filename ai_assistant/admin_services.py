# ai_assistant/admin_services.py
"""
Admin-focused AI Assistant Service
Provides analytics, reports, user performance insights, and system monitoring
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional, Any, List, Tuple, Iterator
import logging
import time
from datetime import datetime, timedelta
from decimal import Decimal
from django.db.models import Sum, Count, Avg, Q
from django.conf import settings
from django.contrib.auth import get_user_model

try:
    import ollama  # type: ignore
except Exception:
    ollama = None

from .models import AIConversation, AIMessage

logger = logging.getLogger(__name__)

User = get_user_model()
AdminAIMode = Literal["analytics", "user_performance", "transaction_analysis", "system_health", "general"]


@dataclass
class AdminAIResponse:
    """Response structure for admin AI queries."""
    mode: AdminAIMode
    reply: str
    used_model: str
    raw: Any
    conversation: Optional[AIConversation]
    data: Optional[dict] = None  # Additional structured data for charts/tables


def _get_model_name() -> str:
    return getattr(settings, "OLLAMA_MODEL_NAME", "llama3")


def _ollama_timeout() -> int:
    return int(getattr(settings, "AI_ASSISTANT_OLLAMA_TIMEOUT", 20))


def _build_admin_context(admin_user: User, context_type: str = "general") -> str:
    """
    Build comprehensive admin context with system-wide statistics.
    """
    lines: List[str] = []
    
    try:
        # Get Transaction model
        from core.models import Transaction
        
        # Time ranges for analysis
        now = datetime.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=7)
        month_start = today_start - timedelta(days=30)
        
        # === USER STATISTICS ===
        total_users = User.objects.count()
        active_users_today = User.objects.filter(last_login__gte=today_start).count()
        active_users_week = User.objects.filter(last_login__gte=week_start).count()
        new_users_week = User.objects.filter(date_joined__gte=week_start).count()
        
        lines.append("=== USER STATISTICS ===")
        lines.append(f"Total registered users: {total_users}")
        lines.append(f"Active today: {active_users_today}")
        lines.append(f"Active this week: {active_users_week}")
        lines.append(f"New registrations this week: {new_users_week}")
        lines.append("")
        
        # === TRANSACTION OVERVIEW ===
        total_transactions = Transaction.objects.count()
        transactions_today = Transaction.objects.filter(created_at__gte=today_start).count()
        transactions_week = Transaction.objects.filter(created_at__gte=week_start).count()
        transactions_month = Transaction.objects.filter(created_at__gte=month_start).count()
        
        lines.append("=== TRANSACTION OVERVIEW ===")
        lines.append(f"Total transactions: {total_transactions}")
        lines.append(f"Today: {transactions_today}")
        lines.append(f"This week: {transactions_week}")
        lines.append(f"This month: {transactions_month}")
        lines.append("")
        
        # === FINANCIAL METRICS ===
        # Note: Transaction model doesn't have 'status', so we count all transactions
        volume_today = Transaction.objects.filter(
            created_at__gte=today_start
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        volume_week = Transaction.objects.filter(
            created_at__gte=week_start
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        volume_month = Transaction.objects.filter(
            created_at__gte=month_start
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        avg_transaction = Transaction.objects.aggregate(
            avg=Avg('amount')
        )['avg'] or Decimal('0')
        
        lines.append("=== FINANCIAL METRICS ===")
        lines.append(f"Transaction volume today: ${volume_today:,.2f}")
        lines.append(f"Transaction volume this week: ${volume_week:,.2f}")
        lines.append(f"Transaction volume this month: ${volume_month:,.2f}")
        lines.append(f"Average transaction amount: ${avg_transaction:,.2f}")
        lines.append("")
        
        # === TRANSACTION STATUS BREAKDOWN ===
        # Since there's no status field, show breakdown by tx_type instead
        type_breakdown = Transaction.objects.values('tx_type').annotate(
            count=Count('id'),
            total=Sum('amount')
        ).order_by('-count')
        
        if type_breakdown:
            lines.append("=== TRANSACTION TYPE BREAKDOWN ===")
            for item in type_breakdown:
                tx_type = item['tx_type'] or 'Unknown'
                count = item['count']
                total = item['total'] or Decimal('0')
                lines.append(f"- {tx_type}: {count} transactions (${total:,.2f})")
            lines.append("")
        
        # === TOP USERS BY TRANSACTION VOLUME ===
        top_users = Transaction.objects.filter(
            created_at__gte=month_start
        ).values('user__id', 'user__username', 'user__email').annotate(
            transaction_count=Count('id'),
            total_volume=Sum('amount')
        ).order_by('-total_volume')[:10]
        
        if top_users:
            lines.append("=== TOP 10 USERS BY VOLUME (This Month) ===")
            for idx, user_data in enumerate(top_users, 1):
                username = user_data['user__username'] or user_data['user__email']
                count = user_data['transaction_count']
                volume = user_data['total_volume'] or Decimal('0')
                lines.append(f"{idx}. {username}: {count} transactions, ${volume:,.2f}")
            lines.append("")
        
        # === RECENT HIGH-VALUE TRANSACTIONS ===
        high_value_threshold = Decimal('1000.00')  # Configurable threshold
        recent_high_value = Transaction.objects.filter(
            created_at__gte=week_start,
            amount__gte=high_value_threshold
        ).order_by('-amount')[:5]
        
        if recent_high_value:
            lines.append(f"=== RECENT HIGH-VALUE TRANSACTIONS (>${high_value_threshold}) ===")
            for tx in recent_high_value:
                username = tx.user.username if tx.user else "Unknown"
                amount = tx.amount
                tx_type = tx.tx_type or "Unknown"
                created = tx.created_at.strftime("%Y-%m-%d %H:%M")
                lines.append(f"- ${amount:,.2f} ({tx_type}) by {username} ({created})")
            lines.append("")
        
        # === SYSTEM HEALTH INDICATORS ===
        # Calculate transaction rate trends
        transactions_yesterday = Transaction.objects.filter(
            created_at__gte=today_start - timedelta(days=1),
            created_at__lt=today_start
        ).count()
        
        lines.append("=== SYSTEM HEALTH ===")
        lines.append(f"Transactions today: {transactions_today}")
        lines.append(f"Transactions yesterday: {transactions_yesterday}")
        
        if transactions_yesterday > 0:
            change_pct = ((transactions_today - transactions_yesterday) / transactions_yesterday) * 100
            if change_pct > 0:
                lines.append(f"📈 Transaction volume up {change_pct:.1f}% from yesterday")
            elif change_pct < 0:
                lines.append(f"📉 Transaction volume down {abs(change_pct):.1f}% from yesterday")
            else:
                lines.append("➡️ Transaction volume stable")
        
        # Check for anomalies
        if transactions_today > 0 and avg_transaction > 0:
            avg_today = volume_today / transactions_today
            if avg_today > avg_transaction * Decimal('2.0'):
                lines.append("⚠️ WARNING: Average transaction size unusually high today")
            elif avg_today < avg_transaction * Decimal('0.5'):
                lines.append("⚠️ WARNING: Average transaction size unusually low today")
        
    except Exception as e:
        logger.exception("Error building admin context: %s", e)
        lines.append(f"⚠️ Error gathering some statistics: {str(e)}")
    
    if not lines:
        return "No system data available."
    
    return "\n".join(lines)


def _build_user_performance_context(user_id: int) -> str:
    """
    Build detailed performance context for a specific user.
    """
    lines: List[str] = []
    
    try:
        from core.models import Transaction
        
        user = User.objects.get(id=user_id)
        now = datetime.now()
        month_start = now - timedelta(days=30)
        week_start = now - timedelta(days=7)
        
        lines.append(f"=== USER PROFILE: {user.username} ===")
        lines.append(f"Email: {user.email}")
        lines.append(f"Joined: {user.date_joined.strftime('%Y-%m-%d')}")
        lines.append(f"Last login: {user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'Never'}")
        
        # Get balance if available
        balance = getattr(user, 'balance', None)
        if balance is not None:
            lines.append(f"Current balance: ${balance:,.2f}")
        lines.append("")
        
        # Transaction statistics
        total_tx = Transaction.objects.filter(user=user).count()
        
        lines.append("=== TRANSACTION HISTORY ===")
        lines.append(f"Total transactions: {total_tx}")
        
        # Volume analysis
        total_volume = Transaction.objects.filter(
            user=user
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        volume_month = Transaction.objects.filter(
            user=user,
            created_at__gte=month_start
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        volume_week = Transaction.objects.filter(
            user=user,
            created_at__gte=week_start
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        lines.append("")
        lines.append("=== FINANCIAL ACTIVITY ===")
        lines.append(f"Lifetime volume: ${total_volume:,.2f}")
        lines.append(f"Volume this week: ${volume_week:,.2f}")
        lines.append(f"Volume this month: ${volume_month:,.2f}")
        
        avg_tx = Transaction.objects.filter(
            user=user
        ).aggregate(avg=Avg('amount'))['avg'] or Decimal('0')
        lines.append(f"Average transaction: ${avg_tx:,.2f}")
        lines.append("")
        
        # Transaction type breakdown for this user
        user_tx_types = Transaction.objects.filter(
            user=user
        ).values('tx_type').annotate(
            count=Count('id'),
            total=Sum('amount')
        ).order_by('-count')
        
        if user_tx_types:
            lines.append("=== TRANSACTION TYPES ===")
            for item in user_tx_types[:5]:  # Top 5 types
                tx_type = item['tx_type'] or 'Unknown'
                count = item['count']
                total = item['total'] or Decimal('0')
                lines.append(f"- {tx_type}: {count} times, ${total:,.2f} total")
            lines.append("")
        
        # Recent transactions
        recent = Transaction.objects.filter(user=user).order_by('-created_at')[:10]
        if recent:
            lines.append("=== RECENT TRANSACTIONS ===")
            for tx in recent:
                date = tx.created_at.strftime("%Y-%m-%d %H:%M")
                tx_type = tx.tx_type or 'Unknown'
                lines.append(f"- [{date}] {tx_type}: ${tx.amount:,.2f}")
        
    except User.DoesNotExist:
        lines.append(f"❌ User with ID {user_id} not found")
    except Exception as e:
        logger.exception("Error building user performance context: %s", e)
        lines.append(f"⚠️ Error: {str(e)}")
    
    return "\n".join(lines)


def _build_admin_system_prompt(mode: AdminAIMode) -> str:
    """
    Build system prompt for admin-focused AI assistant.
    """
    base = (
        "You are the SavingDM Admin AI Assistant.\n"
        "Your role is to help administrators analyze system data, monitor performance, "
        "and generate insights about user behavior and transaction patterns.\n"
        "\n"
        "Core responsibilities:\n"
        "1) Analyze transaction patterns and identify trends\n"
        "2) Evaluate user performance and engagement metrics\n"
        "3) Generate reports on system health and financial metrics\n"
        "4) Identify anomalies, risks, or areas requiring attention\n"
        "5) Provide actionable recommendations for system optimization\n"
        "\n"
        "Guidelines:\n"
        "- Be analytical and data-driven in your responses\n"
        "- Highlight key metrics and trends clearly\n"
        "- Use bullet points and structured formatting\n"
        "- Flag any concerning patterns or anomalies\n"
        "- Provide context with percentages and comparisons\n"
        "- Only use data provided in the context - never invent statistics\n"
        "- When asked about specific users, focus on performance metrics, not personal details\n"
        "- Suggest actionable next steps when appropriate\n"
    )
    
    if mode == "analytics":
        extra = (
            "\nMode: ANALYTICS\n"
            "Focus on: Overall system metrics, trends over time, growth patterns, "
            "comparative analysis, and identifying significant changes in user behavior or transaction volume.\n"
        )
    elif mode == "user_performance":
        extra = (
            "\nMode: USER PERFORMANCE\n"
            "Focus on: Individual user metrics, transaction success rates, volume analysis, "
            "engagement patterns, and identifying high-value or at-risk users.\n"
        )
    elif mode == "transaction_analysis":
        extra = (
            "\nMode: TRANSACTION ANALYSIS\n"
            "Focus on: Transaction patterns, success/failure rates, transaction types distribution, "
            "high-value transactions, suspicious patterns, and processing efficiency.\n"
        )
    elif mode == "system_health":
        extra = (
            "\nMode: SYSTEM HEALTH\n"
            "Focus on: System performance indicators, error rates, pending transactions, "
            "processing bottlenecks, and areas requiring immediate attention.\n"
        )
    else:
        extra = (
            "\nMode: GENERAL ADMIN\n"
            "You may combine analytics, user performance, and system health insights as appropriate.\n"
        )
    
    return base + extra


def ask_admin_ai_assistant(
    *,
    admin_user: User,
    message: str,
    mode: Optional[AdminAIMode] = "general",
    conversation: Optional[AIConversation] = None,
    stream: bool = False,
    context_data: Optional[dict] = None,
) -> Any:
    """
    Admin-focused AI assistant for analytics and reporting.
    
    Args:
        admin_user: The admin user making the query
        message: The admin's question or request
        mode: Type of admin analysis
        conversation: Optional conversation for context
        stream: Whether to stream the response
        context_data: Optional additional context (e.g., specific user_id)
    
    Returns:
        AdminAIResponse or (generator, finalizer) tuple if streaming
    """
    if not admin_user.is_staff:
        logger.warning("Non-admin user %s attempted to use admin AI assistant", admin_user.id)
        return AdminAIResponse(
            mode=mode or "general",
            reply="⚠️ Admin access required. This assistant is only available to administrators.",
            used_model="access-control",
            raw={},
            conversation=conversation,
        )
    
    if mode not in ("analytics", "user_performance", "transaction_analysis", "system_health", "general"):
        mode = "general"
    
    # Build appropriate context
    if context_data and "user_id" in context_data:
        # Specific user analysis
        admin_context = _build_user_performance_context(context_data["user_id"])
    else:
        # System-wide analysis
        admin_context = _build_admin_context(admin_user, context_type=mode)
    
    system_prompt = _build_admin_system_prompt(mode)
    model_name = _get_model_name()
    
    messages: List[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "system", "content": "Current System Data:\n" + admin_context},
    ]
    
    # Add conversation history if available
    if conversation is not None:
        recent_messages = list(conversation.messages.order_by("-created_at")[:20])[::-1]
        for m in recent_messages:
            role = m.role if m.role in {"user", "assistant", "system"} else "user"
            messages.append({"role": role, "content": m.content or ""})
    
    # Add current admin question
    messages.append({"role": "user", "content": message})
    
    use_ollama = bool(getattr(settings, "AI_ASSISTANT_USE_OLLAMA", True))
    
    if use_ollama and ollama is not None:
        # Non-streaming
        if not stream:
            try:
                timeout = _ollama_timeout()
                raw_result = ollama.chat(model=model_name, messages=messages, timeout=timeout)
                
                # Extract response
                reply_text = ""
                if isinstance(raw_result, dict):
                    msg = raw_result.get("message", {})
                    if isinstance(msg, dict):
                        reply_text = msg.get("content", "")
                elif hasattr(raw_result, "message"):
                    reply_text = getattr(raw_result.message, "content", "")
                
                if not reply_text:
                    reply_text = str(raw_result)
                
                used_model = getattr(raw_result, "model", model_name)
                
                return AdminAIResponse(
                    mode=mode,
                    reply=reply_text,
                    used_model=used_model,
                    raw=raw_result,
                    conversation=conversation,
                )
                
            except Exception as e:
                logger.exception("Ollama admin assistant failed: %s", e)
                return _admin_fallback_response(mode, conversation, message, admin_context)
        
        # Streaming
        else:
            try:
                stream_iter = ollama.chat(model=model_name, messages=messages, stream=True)
                
                def gen() -> Iterator[str]:
                    try:
                        for item in stream_iter:
                            chunk = ""
                            if isinstance(item, dict):
                                msg = item.get("message", {})
                                if isinstance(msg, dict):
                                    chunk = msg.get("content", "")
                            elif hasattr(item, "message"):
                                chunk = getattr(item.message, "content", "")
                            
                            if chunk:
                                yield chunk
                    except Exception as e:
                        logger.exception("Error in admin AI stream: %s", e)
                
                def finalizer() -> AdminAIResponse:
                    try:
                        raw_result = ollama.chat(model=model_name, messages=messages)
                        reply_text = ""
                        if isinstance(raw_result, dict):
                            msg = raw_result.get("message", {})
                            if isinstance(msg, dict):
                                reply_text = msg.get("content", "")
                        
                        used_model = getattr(raw_result, "model", model_name)
                        return AdminAIResponse(
                            mode=mode,
                            reply=reply_text,
                            used_model=used_model,
                            raw=raw_result,
                            conversation=conversation,
                        )
                    except Exception as e:
                        logger.exception("Failed finalizer in admin AI: %s", e)
                        return _admin_fallback_response(mode, conversation, message, admin_context)
                
                return gen(), finalizer
                
            except Exception as e:
                logger.exception("Admin AI streaming failed: %s", e)
    
    # Fallback
    return _admin_fallback_response(mode, conversation, message, admin_context)


def _admin_fallback_response(
    mode: AdminAIMode,
    conversation: Optional[AIConversation],
    message: str,
    context: str,
) -> AdminAIResponse:
    """
    Fallback response when Ollama is not available.
    Provides basic analysis based on the context data.
    """
    reply = f"Admin Assistant (Fallback Mode)\n\n"
    reply += "I've analyzed the system data:\n\n"
    reply += context
    reply += "\n\nNote: AI analysis unavailable. This is raw data output. "
    reply += "For AI-powered insights, please ensure Ollama is configured.\n"
    
    return AdminAIResponse(
        mode=mode,
        reply=reply,
        used_model="fallback-v1",
        raw={"fallback": True, "mode": mode},
        conversation=conversation,
    )