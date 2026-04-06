import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from vault.honeypot_models import HoneypotEntry


@override_settings(HONEYPOT={"ENABLED": False})
class HoneypotTriggerViewTests(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.user = get_user_model().objects.create_user(
			username="alice",
			email="alice@example.com",
			password="StrongPass123!",
		)
		self.client.force_authenticate(user=self.user)

	def _create_entry(self, **kwargs):
		defaults = {
			"user": self.user,
			"category": "api_key",
			"provider": "stripe",
			"fake_secret": "sk_test_decoy_value",
			"honeypot_id": uuid.uuid4(),
			"generator": "fallback",
		}
		defaults.update(kwargs)
		return HoneypotEntry.objects.create(**defaults)

	@patch("ai_engine.honeypot_alert_api.send_breach_alert")
	def test_trigger_marks_entry_and_dispatches_email(self, mock_send_breach_alert):
		entry = self._create_entry()
		mock_send_breach_alert.return_value = {
			"success": True,
			"alert_id": "alert-123",
			"message_id": "message-123",
			"error": None,
		}

		response = self.client.post(
			"/api/honeypot/trigger/",
			{
				"entry_id": str(entry.id),
				"severity": "high",
				"triggered_ip": "203.0.113.10",
			},
			format="json",
		)

		self.assertEqual(response.status_code, 200)
		payload = response.json()
		self.assertEqual(payload["message"], "Honeypot alert recorded.")
		self.assertTrue(payload["email_alert"]["attempted"])
		self.assertTrue(payload["email_alert"]["success"])

		entry.refresh_from_db()
		self.assertTrue(entry.is_triggered)
		self.assertEqual(entry.triggered_ip, "203.0.113.10")
		self.assertIsNotNone(entry.triggered_at)

		self.assertEqual(mock_send_breach_alert.call_count, 1)
		call_kwargs = mock_send_breach_alert.call_args.kwargs
		self.assertEqual(call_kwargs["recipient_email"], self.user.email)
		self.assertEqual(call_kwargs["recipient_name"], self.user.username)
		self.assertEqual(call_kwargs["breach_details"]["category"], "api_key")
		self.assertEqual(call_kwargs["breach_details"]["severity"], "high")

	@patch("ai_engine.honeypot_alert_api.send_breach_alert")
	def test_trigger_with_missing_user_email_skips_dispatch(self, mock_send_breach_alert):
		user_without_email = get_user_model().objects.create_user(
			username="noemail",
			email="",
			password="StrongPass123!",
		)

		entry = self._create_entry(user=user_without_email)
		self.client.force_authenticate(user=user_without_email)

		response = self.client.post(
			"/api/honeypot/trigger/",
			{"entry_id": str(entry.id)},
			format="json",
		)

		self.assertEqual(response.status_code, 200)
		payload = response.json()
		self.assertFalse(payload["email_alert"]["attempted"])
		self.assertFalse(payload["email_alert"]["success"])
		self.assertIn("no email", payload["email_alert"]["reason"].lower())

		entry.refresh_from_db()
		self.assertTrue(entry.is_triggered)
		self.assertIsNotNone(entry.triggered_at)
		self.assertEqual(mock_send_breach_alert.call_count, 0)
