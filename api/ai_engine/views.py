"""
AI Engine Views — Ephemeral Secret Audit

POST /api/audit/
  - Accepts { "secret": "..." }
  - Returns a risk profile JSON
  - NEVER saves the secret to the database
  - Requires JWT authentication
"""

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import AuditRequestSerializer
from .auditor import analyze


class AuditView(APIView):
    """
    Ephemeral secret analysis endpoint.

    Receives a plaintext secret, runs detector + model analysis,
    and returns a structured risk profile. The secret is never
    persisted anywhere — it lives only in request memory.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = AuditRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        secret = serializer.validated_data["secret"]

        # Analyze — ephemeral, no DB writes
        risk_profile = analyze(secret)

        return Response(risk_profile, status=status.HTTP_200_OK)
