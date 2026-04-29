from rest_framework import serializers

from core.policies import serialize_datetime


class PaymentVerifySerializer(serializers.Serializer):
    razorpay_order_id = serializers.CharField(required=False, allow_blank=True)
    razorpay_payment_id = serializers.CharField(required=False, allow_blank=True)
    razorpay_signature = serializers.CharField(required=False, allow_blank=True)


def serialize_payment(payment):
    return {
        "id": str(payment.id),
        "contract_id": str(payment.contract.id),
        "job_id": str(payment.job.id),
        "client_id": str(payment.client.id),
        "freelancer_id": str(payment.freelancer.id),
        "amount": round(float(payment.amount or 0), 2),
        "currency": payment.currency,
        "provider": payment.provider,
        "provider_mode": payment.provider_mode,
        "status": payment.status,
        "provider_order_id": payment.provider_order_id,
        "provider_payment_id": payment.provider_payment_id,
        "created_at": serialize_datetime(payment.created_at),
        "updated_at": serialize_datetime(payment.updated_at),
        "verified_at": serialize_datetime(payment.verified_at),
    }
