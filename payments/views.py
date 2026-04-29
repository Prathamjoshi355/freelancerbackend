import base64
import hashlib
import hmac
import json
import uuid
import urllib.error
import urllib.request
from datetime import datetime

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.env import get_env
from core.policies import require_client_ready, require_profile_complete
from jobs.models import Contract
from .models import Payment
from .serializers import PaymentVerifySerializer, serialize_payment


def payments_mode():
    explicit = (get_env("PAYMENTS_MODE", "") or "").strip().lower()
    if explicit:
        return explicit
    if get_env("RAZORPAY_KEY_ID") and get_env("RAZORPAY_KEY_SECRET"):
        return "razorpay"
    return "mock"


def create_provider_order(amount, receipt):
    mode = payments_mode()
    amount_in_paise = int(round(float(amount) * 100))
    key_id = get_env("RAZORPAY_KEY_ID", "rzp_test_mock")
    if mode != "razorpay":
        return {
            "mode": "mock",
            "key_id": key_id,
            "order": {
                "id": f"order_mock_{uuid.uuid4().hex[:14]}",
                "amount": amount_in_paise,
                "currency": "INR",
                "receipt": receipt,
            },
        }

    key_secret = get_env("RAZORPAY_KEY_SECRET", required=True)
    payload = json.dumps({"amount": amount_in_paise, "currency": "INR", "receipt": receipt}).encode()
    auth = base64.b64encode(f"{key_id}:{key_secret}".encode()).decode()
    request = urllib.request.Request(
        "https://api.razorpay.com/v1/orders",
        data=payload,
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            order = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()
        raise ValueError(f"Razorpay order creation failed: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ValueError(f"Razorpay network failure: {exc.reason}") from exc

    return {"mode": "razorpay", "key_id": key_id, "order": order}


def verify_signature(order_id, payment_id, signature):
    mode = payments_mode()
    if mode != "razorpay":
        return True

    key_secret = get_env("RAZORPAY_KEY_SECRET", required=True)
    body = f"{order_id}|{payment_id}".encode()
    expected = hmac.new(key_secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


class PaymentListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        require_profile_complete(request.user)
        if request.user.role == "client":
            payments = Payment.objects(client=request.user).order_by("-created_at")
        else:
            payments = Payment.objects(freelancer=request.user).order_by("-created_at")
        return Response({"results": [serialize_payment(payment) for payment in payments]})


class PaymentCreateOrderView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, contract_id):
        require_client_ready(request.user)
        contract = Contract.objects(id=contract_id).first()
        if contract is None:
            return Response({"detail": "Contract not found."}, status=status.HTTP_404_NOT_FOUND)
        if str(contract.client.id) != str(request.user.id):
            return Response({"detail": "You can only create payments for your own contracts."}, status=status.HTTP_403_FORBIDDEN)

        try:
            provider = create_provider_order(contract.agreed_amount, receipt=f"contract-{contract.id}")
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        payment = Payment.objects(contract=contract).first() or Payment(
            contract=contract,
            job=contract.job,
            client=contract.client,
            freelancer=contract.freelancer,
            amount=contract.agreed_amount,
        )
        payment.provider_mode = provider["mode"]
        payment.provider_order_id = provider["order"]["id"]
        payment.provider_payload = provider["order"]
        payment.status = "created"
        payment.save()

        return Response(
            {
                "payment": serialize_payment(payment),
                "checkout": {
                    "mode": provider["mode"],
                    "key_id": provider["key_id"],
                    "order": provider["order"],
                },
            }
        )


class PaymentVerifyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, payment_id):
        require_client_ready(request.user)
        payment = Payment.objects(id=payment_id).first()
        if payment is None:
            return Response({"detail": "Payment not found."}, status=status.HTTP_404_NOT_FOUND)
        if str(payment.client.id) != str(request.user.id):
            return Response({"detail": "You can only verify your own payments."}, status=status.HTTP_403_FORBIDDEN)

        serializer = PaymentVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        order_id = serializer.validated_data.get("razorpay_order_id") or payment.provider_order_id
        payment_id_value = serializer.validated_data.get("razorpay_payment_id") or f"pay_mock_{uuid.uuid4().hex[:12]}"
        signature = serializer.validated_data.get("razorpay_signature", "")

        if not verify_signature(order_id, payment_id_value, signature):
            payment.status = "failed"
            payment.save()
            return Response({"detail": "Payment signature verification failed."}, status=status.HTTP_400_BAD_REQUEST)

        payment.provider_payment_id = payment_id_value
        payment.provider_signature = signature
        payment.status = "verified"
        payment.verified_at = datetime.utcnow()
        payment.save()

        payment.contract.payment_status = "paid"
        if payment.contract.status == "active":
            payment.contract.status = "funded"
        payment.contract.save()

        return Response({"payment": serialize_payment(payment)})
