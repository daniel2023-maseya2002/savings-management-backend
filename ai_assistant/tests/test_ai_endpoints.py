# ai_assistant/tests/test_ai_endpoints.py
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from ai_assistant.models import AIConversation, AIMessage

User = get_user_model()


class AIEndpointsTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="tester_ai", email="ai@test.local", password="pass1234"
        )
        # give user a balance attribute if using custom user model
        if hasattr(self.user, "balance"):
            self.user.balance = 1000.00
            self.user.save()

        # Authentication (session based for tests)
        self.client.force_authenticate(user=self.user)

    @patch("ai_assistant.services.ollama.chat")
    def test_create_conversation_and_reply(self, mock_ollama_chat):
        # Mock a predictable response from ollama.chat
        mock_ollama_chat.return_value = {"message": {"content": "Hello from AI (mocked)"}}

        url = reverse("ai-assistant-chat")  # make sure this name matches your urls
        data = {"mode": "budget", "message": "How much can I send this month?"}

        resp = self.client.post(url, data, format="json")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("conversation_id", resp.data)
        self.assertIn("reply", resp.data)
        self.assertEqual(resp.data["reply"], "Hello from AI (mocked)")

        conv_id = resp.data["conversation_id"]
        conv = AIConversation.objects.get(id=conv_id)
        # two messages created in the view: user + assistant
        msgs = AIMessage.objects.filter(conversation=conv).order_by("created_at")
        self.assertGreaterEqual(msgs.count(), 2)
        self.assertEqual(msgs[0].role, AIMessage.ROLE_USER)
        self.assertEqual(msgs[1].role, AIMessage.ROLE_ASSISTANT)
        self.assertIn("How much can I send", msgs[0].content)

    def test_list_conversations(self):
        # create a couple conversations for this user
        AIConversation.objects.create(user=self.user, mode="budget", title="Conv A")
        AIConversation.objects.create(user=self.user, mode="general", title="Conv B")

        url = reverse("ai-conversations-list")
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        # Should return list of conversations belonging to this user
        self.assertIsInstance(resp.data, list)
        self.assertGreaterEqual(len(resp.data), 2)

    @patch("ai_assistant.services.ollama.chat")
    def test_append_message_and_receive_reply(self, mock_ollama_chat):
        mock_ollama_chat.return_value = {"message": {"content": "Assistant reply (mock)"}}
        conv = AIConversation.objects.create(user=self.user, mode="transactions", title="Tx conv")
        url = reverse("ai-conversation-append-reply", args=[conv.id])
        data = {"message": "Please analyze my spending"}

        resp = self.client.post(url, data, format="json")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("reply", resp.data)
        self.assertEqual(resp.data["reply"], "Assistant reply (mock)")

        # Ensure messages saved
        msgs = AIMessage.objects.filter(conversation=conv).order_by("created_at")
        # should have at least 2 messages (user + assistant)
        self.assertGreaterEqual(msgs.count(), 2)
        self.assertEqual(msgs.last().role, AIMessage.ROLE_ASSISTANT)
