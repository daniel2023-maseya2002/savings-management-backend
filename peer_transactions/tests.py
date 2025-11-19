# peer_transactions/tests.py
from django.test import TestCase
from django.contrib.auth import get_user_model
from decimal import Decimal
from .models import UserBalance, Transfer
from .views import perform_atomic_transfer

User = get_user_model()

class TransferTests(TestCase):
    def setUp(self):
        self.u1 = User.objects.create_user(username="u1", password="p")
        self.u2 = User.objects.create_user(username="u2", password="p")
        UserBalance.objects.create(user=self.u1, balance=Decimal("100.00"))
        UserBalance.objects.create(user=self.u2, balance=Decimal("10.00"))

    def test_successful_transfer(self):
        t = Transfer.objects.create(created_by=self.u1, to_user=self.u2, amount=Decimal("20.00"))
        res = perform_atomic_transfer(t)
        self.assertTrue(res["ok"])
        self.u1.refresh_from_db()
        self.u2.refresh_from_db()
        self.assertEqual(UserBalance.objects.get(user=self.u1).balance, Decimal("80.00"))
        self.assertEqual(UserBalance.objects.get(user=self.u2).balance, Decimal("30.00"))
        t.refresh_from_db()
        self.assertEqual(t.status, Transfer.STATUS_COMPLETED)

    def test_insufficient(self):
        t = Transfer.objects.create(created_by=self.u2, to_user=self.u1, amount=Decimal("200.00"))
        res = perform_atomic_transfer(t)
        self.assertFalse(res["ok"])
        t.refresh_from_db()
        self.assertEqual(t.status, Transfer.STATUS_FAILED)

