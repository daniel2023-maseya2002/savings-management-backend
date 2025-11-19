# peer_transactions/views.py
from decimal import Decimal, ROUND_DOWN, getcontext

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import EmailMultiAlternatives
from django.db import transaction, models
from django.shortcuts import get_object_or_404
from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError

from .models import Transfer  # ⬅️ NOTE: we no longer import UserBalance here
from .serializers import TransferCreateSerializer, TransferSerializer
from .permissions import IsSenderOrAdmin

getcontext().prec = 28

User = get_user_model()

# ====== CONFIG: FEES & FEE ACCOUNT ======
# Default 10% fee if not overridden in settings.py
FEE_PERCENT = getattr(
    settings,
    "PEER_TRANSACTIONS_FEE_PERCENT",
    Decimal("0.10"),
)

# Prefer username-based fee account (your "saving_fee" user)
FEE_ACCOUNT_USERNAME = getattr(
    settings,
    "PEER_TRANSACTIONS_FEE_ACCOUNT_USERNAME",
    None,
)

# Optional fallback: user id of fee account
FEE_ACCOUNT_ID = getattr(
    settings,
    "PEER_TRANSACTIONS_FEE_ACCOUNT_ID",
    None,
)

# Optional notifications app
try:
    from notifications.models import Notification
except Exception:  # noqa
    Notification = None


# -------------------------------------------------------------------
#  Email helper (HTML + plaintext)
# -------------------------------------------------------------------
def _send_html_email(subject, to_email, plain_text, html_content):
    """
    Simple wrapper around EmailMultiAlternatives.
    - Uses DEFAULT_FROM_EMAIL from settings.
    - Fail silently so a temporary SMTP issue doesn't break transfers.
    """
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@savingdm.com")
    msg = EmailMultiAlternatives(subject, plain_text, from_email, [to_email])
    msg.attach_alternative(html_content, "text/html")
    msg.send(fail_silently=True)


# -------------------------------------------------------------------
#  Resolve fee account (admin/system wallet)
# -------------------------------------------------------------------
def _resolve_fee_account_user():
    """
    1. If PEER_TRANSACTIONS_FEE_ACCOUNT_USERNAME is set, try that.
    2. Else, if PEER_TRANSACTIONS_FEE_ACCOUNT_ID is set, try that.
    3. Else, return None (fee money has nowhere to go).
    """
    if FEE_ACCOUNT_USERNAME:
        try:
            return User.objects.get(username=FEE_ACCOUNT_USERNAME)
        except User.DoesNotExist:
            return None

    if FEE_ACCOUNT_ID:
        try:
            return User.objects.get(pk=FEE_ACCOUNT_ID)
        except User.DoesNotExist:
            return None

    return None


# -------------------------------------------------------------------
#  In-app + Email notifications for transfers
# -------------------------------------------------------------------
def _send_transfer_notifications(
    transfer: "Transfer",
    from_before: Decimal,
    from_after: Decimal,
    to_before: Decimal,
    to_after: Decimal,
):
    """
    Send:
      1) In-app notification + email to sender ("you sent money…")
      2) In-app notification + email to recipient ("you received money…")

    Includes:
      - amount
      - currency
      - 10% fee (for sender)
      - new balances
    """
    sender = transfer.created_by
    recipient = transfer.to_user
    amount = transfer.amount
    currency = transfer.currency or "USD"
    fee = transfer.fee or Decimal("0.00")

    APP_NAME = "SavingDM"
    # You can replace this placeholder with a real logo URL later
    LOGO_URL = "https://via.placeholder.com/140x40?text=SavingDM"

    # ----- Messages (plain text) -----
    sender_title = "Transfer Sent Successfully"
    sender_msg = (
        f"You sent {amount} {currency} to {recipient.username}. "
        f"Transfer fee (10%) was {fee} {currency}. "
        f"Total debited: {amount + fee} {currency}. "
        f"Your new balance is {from_after}."
    )

    recipient_title = "You Received Money"
    recipient_msg = (
        f"You received {amount} {currency} from {sender.username}. "
        f"No fee was deducted from you. "
        f"Your new balance is {to_after}."
    )

    # ----- HTML template builder -----
    def build_html(title, message, username, amount_value, is_sender: bool):
        # Extra section for fee explanation
        if is_sender:
            fee_line = f"""
                <p style="color:#334155; font-size:14px; margin:6px 0;">
                    <strong>Transfer fee (10%):</strong>
                    <span style="color:#F97316;">{fee} {currency}</span>
                </p>
                <p style="color:#334155; font-size:14px; margin:6px 0;">
                    <strong>Total debited from your wallet:</strong>
                    <span style="color:#EF4444;">{(amount_value + fee)} {currency}</span>
                </p>
            """
        else:
            fee_line = """
                <p style="color:#16A34A; font-size:14px; margin:6px 0;">
                    <strong>No fee was charged on your side for this transfer.</strong>
                </p>
            """

        return f"""
        <html>
        <body style="font-family:Arial, sans-serif; background-color:#0F172A; padding:24px;">
            <div style="max-width:640px; margin:auto; background:#020617; border-radius:16px; padding:24px 28px; border:1px solid #1E293B;">
                <!-- Header / Logo -->
                <div style="text-align:center; margin-bottom:18px;">
                    <img src="{LOGO_URL}" alt="{APP_NAME} Logo" style="max-height:42px; margin-bottom:6px;" />
                    <div style="color:#38BDF8; font-size:13px; letter-spacing:1px; text-transform:uppercase;">
                        Secure Peer Transfer
                    </div>
                </div>

                <!-- Title -->
                <h2 style="color:#E5E7EB; font-size:22px; margin-bottom:6px;">{title}</h2>

                <!-- Greeting -->
                <p style="color:#94A3B8; font-size:14px; line-height:1.7;">
                    Hello <strong>{username}</strong>,
                </p>

                <!-- Main message -->
                <p style="color:#CBD5F5; font-size:14px; line-height:1.7; margin-top:4px;">
                    {message}
                </p>

                <!-- Amount summary pill -->
                <div style="
                    margin-top:18px;
                    padding:14px 16px;
                    border-radius:12px;
                    background:linear-gradient(135deg,#0F766E,#0369A1);
                    color:white;
                    display:flex;
                    justify-content:space-between;
                    align-items:center;
                ">
                    <div>
                        <div style="font-size:12px; text-transform:uppercase; letter-spacing:1px; opacity:0.9;">
                            Amount
                        </div>
                        <div style="font-size:20px; font-weight:bold;">
                            {amount_value} {currency}
                        </div>
                    </div>
                    <div style="text-align:right;">
                        <div style="font-size:11px; text-transform:uppercase; letter-spacing:1px; opacity:0.85;">
                            Fee (10%)
                        </div>
                        <div style="font-size:14px; font-weight:bold;">
                            {fee} {currency}
                        </div>
                    </div>
                </div>

                {fee_line}

                <!-- Footer -->
                <p style="font-size:11px; color:#64748B; margin-top:32px; text-align:center;">
                    You are receiving this email because you have a SavingDM wallet. If this wasn't you,
                    please contact support immediately.
                </p>
                <p style="font-size:11px; color:#475569; text-align:center; margin-top:4px;">
                    © {APP_NAME} — Smart Savings & Peer Transfers
                </p>
            </div>
        </body>
        </html>
        """

    # ----- In-app notifications (if app exists) -----
    if Notification:
        try:
            Notification.objects.create(
                user=sender,
                notif_type=Notification.TYPE_WITHDRAW,  # or a new TYPE_PEER_TRANSFER_OUT if you add it
                title=sender_title,
                message=sender_msg,
                meta={
                    "type": "peer_transfer",
                    "direction": "outgoing",
                    "transfer_id": str(transfer.id),
                    "amount": str(amount),
                    "currency": currency,
                    "other_username": recipient.username,
                    "new_balance": str(from_after),
                    "fee": str(fee),
                },
            )
        except Exception:
            pass

        try:
            Notification.objects.create(
                user=recipient,
                notif_type=Notification.TYPE_DEPOSIT,  # or a new TYPE_PEER_TRANSFER_IN if you add it
                title=recipient_title,
                message=recipient_msg,
                meta={
                    "type": "peer_transfer",
                    "direction": "incoming",
                    "transfer_id": str(transfer.id),
                    "amount": str(amount),
                    "currency": currency,
                    "other_username": sender.username,
                    "new_balance": str(to_after),
                    "fee": "0.00",
                },
            )
        except Exception:
            pass

    # ----- Emails -----
    if sender.email:
        html = build_html(sender_title, sender_msg, sender.username, amount, True)
        _send_html_email(
            subject=f"{APP_NAME} — You Sent {amount} {currency}",
            to_email=sender.email,
            plain_text=sender_msg,
            html_content=html,
        )

    if recipient.email:
        html = build_html(
            recipient_title,
            recipient_msg,
            recipient.username,
            amount,
            False,
        )
        _send_html_email(
            subject=f"{APP_NAME} — You Received {amount} {currency}",
            to_email=recipient.email,
            plain_text=recipient_msg,
            html_content=html,
        )


# -------------------------------------------------------------------
#  Core transfer logic (atomic, with fee) using core.User.balance
# -------------------------------------------------------------------
def perform_atomic_transfer(transfer: "Transfer"):
    """
    Atomic transfer handling with fee, using the same wallet
    as core DepositView / WithdrawView:

      - We use User.balance as the single source of truth.
      - fee  = amount * FEE_PERCENT (10% by default)
      - sender pays amount + fee from user.balance
      - recipient receives `amount` in user.balance
      - fee goes to fee account (SavingDM system wallet) if configured
    """
    amount = Decimal(str(transfer.amount)).quantize(
        Decimal("0.01"),
        rounding=ROUND_DOWN,
    )
    fee = (amount * FEE_PERCENT).quantize(
        Decimal("0.01"),
        rounding=ROUND_DOWN,
    )
    net_amount = amount  # recipient receives 'amount'
    transfer.set_fee_and_net(fee, net_amount)

    sender = transfer.created_by
    recipient = transfer.to_user

    fee_account_user = _resolve_fee_account_user()

    # Build the set of involved user ids
    involved_ids = {sender.id, recipient.id}
    if fee_account_user and fee_account_user.id not in involved_ids:
        involved_ids.add(fee_account_user.id)

    with transaction.atomic():
        # Lock all involved users (same pattern as Deposit/Withdraw)
        locked_users = (
            User.objects.select_for_update()
            .filter(id__in=involved_ids)
            .order_by("id")
        )
        locked_by_id = {u.id: u for u in locked_users}

        sender_user = locked_by_id[sender.id]
        recipient_user = locked_by_id[recipient.id]
        fee_user_locked = locked_by_id.get(fee_account_user.id) if fee_account_user else None

        # Treat None as 0.00 just in case
        sender_balance = sender_user.balance or Decimal("0.00")
        recipient_balance = recipient_user.balance or Decimal("0.00")

        # Sender must cover amount + fee
        total_required = (amount + fee).quantize(
            Decimal("0.01"),
            rounding=ROUND_DOWN,
        )
        if sender_balance < total_required:
            transfer.mark_failed("insufficient_funds")
            return {"ok": False, "reason": "insufficient_funds"}

        # Snapshots before
        f_before = sender_balance
        t_before = recipient_balance
        fa_before = None
        if fee_user_locked:
            fa_before = fee_user_locked.balance or Decimal("0.00")

        # Apply debits / credits
        sender_balance = (sender_balance - total_required).quantize(
            Decimal("0.01"),
            rounding=ROUND_DOWN,
        )
        recipient_balance = (recipient_balance + net_amount).quantize(
            Decimal("0.01"),
            rounding=ROUND_DOWN,
        )

        sender_user.balance = sender_balance
        recipient_user.balance = recipient_balance

        sender_user.save(update_fields=["balance"])
        recipient_user.save(update_fields=["balance"])

        if fee_user_locked:
            fee_balance = (fa_before + fee).quantize(
                Decimal("0.01"),
                rounding=ROUND_DOWN,
            )
            fee_user_locked.balance = fee_balance
            fee_user_locked.save(update_fields=["balance"])
        else:
            fee_balance = None

        # Snapshots after
        from_after = sender_balance
        to_after = recipient_balance

        # Store fee info in metadata
        meta_fee_info = {
            "fee_percent": str(FEE_PERCENT),
            "fee": str(fee),
            "total_debited_from_sender": str(total_required),
        }
        if fee_user_locked:
            meta_fee_info["fee_account_username"] = fee_account_user.username
            meta_fee_info["fee_account_before"] = str(fa_before)
            meta_fee_info["fee_account_after"] = str(fee_balance)

        transfer.metadata = {**(transfer.metadata or {}), "fee_info": meta_fee_info}
        transfer.mark_completed(f_before, from_after, t_before, to_after)

        # Trigger notifications + emails
        _send_transfer_notifications(
            transfer,
            from_before=f_before,
            from_after=from_after,
            to_before=t_before,
            to_after=to_after,
        )

    return {"ok": True, "transfer_id": str(transfer.id)}


# -------------------------------------------------------------------
#  API views
# -------------------------------------------------------------------
class CreateTransferView(generics.CreateAPIView):
    """
    POST /api/peer/transfers/create/
    Body:
      - to_username
      - amount
      - currency
      - reference (optional)
      - note (optional)
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TransferCreateSerializer

    def perform_create(self, serializer):
        transfer = serializer.save()  # status=requested
        result = perform_atomic_transfer(transfer)
        if not result.get("ok"):
            reason = result.get("reason", "transfer_failed")
            if reason == "insufficient_funds":
                raise ValidationError(
                    {
                        "detail": "You do not have enough balance to complete this transfer."
                    }
                )
            raise ValidationError({"detail": reason})


class UserTransfersListView(generics.ListAPIView):
    """
    GET /api/peer/transfers/mine/
    List transfers where the current user is either the sender or the recipient.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TransferSerializer

    def get_queryset(self):
        user = self.request.user
        return (
            Transfer.objects.filter(
                models.Q(created_by=user) | models.Q(to_user=user)
            )
            .order_by("-created_at")
        )


class AdminTransfersListView(generics.ListAPIView):
    """
    GET /api/peer/transfers/admin/

    Admin/staff-only view: shows all transfers in the system.

    Optional query params:
      - ?user_id=<id>    -> filter transfers where this user is sender or recipient
      - ?status=<status> -> filter by status (e.g. 'requested', 'completed', 'failed')
    """
    permission_classes = [permissions.IsAdminUser]
    serializer_class = TransferSerializer

    def get_queryset(self):
        qs = Transfer.objects.select_related("created_by", "to_user").order_by(
            "-created_at"
        )

        user_id = self.request.query_params.get("user_id")
        status_param = self.request.query_params.get("status")

        if user_id:
            qs = qs.filter(
                models.Q(created_by__id=user_id) | models.Q(to_user__id=user_id)
            )

        if status_param:
            qs = qs.filter(status=status_param)

        return qs


class TransferDetailView(generics.RetrieveAPIView):
    """
    GET /api/peer/transfers/<uuid:id>/
    """
    permission_classes = [permissions.IsAuthenticated, IsSenderOrAdmin]
    serializer_class = TransferSerializer
    lookup_field = "id"
    queryset = Transfer.objects.all()


class AdminApproveView(generics.GenericAPIView):
    """
    POST /api/peer/transfers/<uuid:id>/admin-approve/

    Body:
      - action: "complete" or "fail"
      - reason: optional (for "fail")
    """
    permission_classes = [permissions.IsAdminUser]
    serializer_class = TransferSerializer
    queryset = Transfer.objects.all()
    lookup_field = "id"

    def post(self, request, id):
        action = request.data.get("action")
        transfer = get_object_or_404(Transfer, id=id)

        if action == "complete":
            if transfer.status == Transfer.STATUS_COMPLETED:
                return Response(
                    {"detail": "already completed"},
                    status=status.HTTP_200_OK,
                )
            result = perform_atomic_transfer(transfer)
            if not result.get("ok"):
                return Response(
                    {"detail": result.get("reason")},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            return Response({"detail": "completed"})

        if action == "fail":
            transfer.mark_failed(request.data.get("reason", "admin_failed"))
            return Response({"detail": "marked_failed"})

        return Response(
            {"detail": "unknown action"},
            status=status.HTTP_400_BAD_REQUEST,
        )
