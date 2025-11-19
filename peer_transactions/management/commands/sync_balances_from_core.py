# peer_transactions/management/commands/sync_peer_balances.py
from decimal import Decimal, getcontext

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction

from django.contrib.auth import get_user_model

from core.models import Transaction  # your main ledger model
from peer_transactions.models import UserBalance, Transfer

getcontext().prec = 28

User = get_user_model()

FEE_ACCOUNT_ID = getattr(settings, "PEER_TRANSACTIONS_FEE_ACCOUNT_ID", None)


class Command(BaseCommand):
    help = (
        "Rebuilds UserBalance rows from core.Transaction and peer Transfer logs, "
        "including transaction fees."
    )

    def handle(self, *args, **options):
        self.stdout.write(self.style.MIGRATE_HEADING("Rebuilding user balances..."))

        with transaction.atomic():
            # 1) Reset all balances to 0.00
            self.stdout.write("  - Resetting existing UserBalance rows to 0.00")
            UserBalance.objects.all().update(balance=Decimal("0.00"))

            # We'll fill this with user_id -> Decimal balance
            balances = {}

            def add_to_balance(user_id, amount: Decimal):
                if user_id is None:
                    return
                if user_id not in balances:
                    balances[user_id] = Decimal("0.00")
                balances[user_id] += amount

            # 2) Replay core.Transaction (deposits / withdrawals)
            self.stdout.write("  - Applying core.Transaction ledger...")
            qs = Transaction.objects.all()

            for tx in qs.iterator():
                # adapt these field names to your real Transaction model
                user_id = getattr(tx, "user_id", None)
                status = (getattr(tx, "status", "") or "").lower()
                tx_type = (getattr(tx, "tx_type", "") or getattr(tx, "type", "") or "").upper()
                amount = Decimal(str(getattr(tx, "amount", "0")))

                # Only count successful / completed transactions
                if status and status not in ("completed", "success", "successful"):
                    continue

                if tx_type == "DEPOSIT":
                    add_to_balance(user_id, amount)
                elif tx_type in ("WITHDRAW", "WITHDRAWAL"):
                    add_to_balance(user_id, -amount)

            # 3) Replay completed Transfer logs (including fee & net)
            self.stdout.write("  - Applying peer Transfer logs with fees...")
            t_qs = Transfer.objects.filter(status=Transfer.STATUS_COMPLETED)

            for t in t_qs.iterator():
                sender_id = t.created_by_id
                recipient_id = t.to_user_id
                amount = Decimal(str(t.amount))
                fee = Decimal(str(t.fee or 0))

                # sender pays amount + fee
                add_to_balance(sender_id, -(amount + fee))

                # recipient receives amount (net_amount is also stored but we use amount here)
                add_to_balance(recipient_id, amount)

                # optional: platform fee account receives fee
                if FEE_ACCOUNT_ID:
                    try:
                        fee_user = User.objects.get(pk=FEE_ACCOUNT_ID)
                        add_to_balance(fee_user.id, fee)
                    except User.DoesNotExist:
                        # If misconfigured, we just ignore the fee account
                        pass

            # 4) Persist balances into UserBalance rows
            self.stdout.write("  - Writing balances to UserBalance table...")
            for user_id, bal in balances.items():
                user = User.objects.filter(pk=user_id).first()
                if not user:
                    continue
                ub, _ = UserBalance.objects.get_or_create(
                    user=user, defaults={"balance": Decimal("0.00")}
                )
                ub.balance = bal.quantize(Decimal("0.01"))
                ub.save(update_fields=["balance", "updated_at"])

        self.stdout.write(self.style.SUCCESS("User balances rebuilt successfully."))
