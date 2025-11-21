# peer_transactions/tests/test_peer_transfers.py
from decimal import Decimal
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from peer_transactions.models import Transfer

User = get_user_model()


class PeerTransfersTests(APITestCase):
    def setUp(self):
        # create sender, recipient and fee account (optional)
        self.sender = User.objects.create_user(
            username="alice", email="alice@test.local", password="pass123"
        )
        self.recipient = User.objects.create_user(
            username="bob", email="bob@test.local", password="pass123"
        )

        # If your User model has a "balance" field, set initial balances
        if hasattr(self.sender, "balance"):
            self.sender.balance = Decimal("1000.00")
            self.sender.save(update_fields=["balance"])
        if hasattr(self.recipient, "balance"):
            self.recipient.balance = Decimal("200.00")
            self.recipient.save(update_fields=["balance"])

        # Authenticate as sender for create endpoint
        self.client.force_authenticate(user=self.sender)

    def test_create_transfer_and_balance_update(self):
        url = reverse("peer-transfer-create")  # ensure name matches your urls

        payload = {
            "to_username": self.recipient.username,
            "amount": "200.00",
            "currency": "USD",
            "reference": "Test transfer",
            "note": "From tests",
        }

        resp = self.client.post(url, payload, format="json")
        # If transfer succeeded it should return 201 or 200 depending on view; CreateAPIView returns 201
        self.assertIn(resp.status_code, (status.HTTP_201_CREATED, status.HTTP_200_OK))

        # Refresh users from DB
        self.sender.refresh_from_db()
        self.recipient.refresh_from_db()

        # Fee is 10% by default: fee = 20.00, total debited = 220.00
        # Sender initial 1000.00 -> 780.00
        expected_sender_balance = Decimal("1000.00") - Decimal("200.00") - Decimal("20.00")

        # Recipient initial 200.00 -> 400.00
        expected_recipient_balance = Decimal("200.00") + Decimal("200.00")

        # If balances exist on user model assert them
        if hasattr(self.sender, "balance"):
            self.assertEqual(self.sender.balance.quantize(Decimal("0.01")), expected_sender_balance.quantize(Decimal("0.01")))

        if hasattr(self.recipient, "balance"):
            self.assertEqual(self.recipient.balance.quantize(Decimal("0.01")), expected_recipient_balance.quantize(Decimal("0.01")))

        # Ensure Transfer record exists
        transfer = Transfer.objects.filter(created_by=self.sender, to_user=self.recipient).order_by("-created_at").first()
        self.assertIsNotNone(transfer)
        self.assertEqual(str(transfer.amount), "200.00")
        self.assertEqual(str(transfer.fee), "20.00")
        self.assertEqual(transfer.status.lower(), "completed")
