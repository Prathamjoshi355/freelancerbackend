from rest_framework import serializers
from .models import Transaction, Payout


class TransactionSerializer(serializers.Serializer):
    """Serializer for Transaction model"""
    id = serializers.CharField(read_only=True)
    client_id = serializers.CharField()
    freelancer_id = serializers.CharField()
    proposal_id = serializers.CharField()
    
    amount = serializers.FloatField()
    fees = serializers.FloatField(default=0)
    net_amount = serializers.FloatField()
    
    status = serializers.ChoiceField(choices=['pending', 'completed', 'failed', 'refunded'])
    payment_method = serializers.ChoiceField(choices=['stripe', 'paypal', 'invoice'])
    transaction_id = serializers.CharField(required=False)
    
    description = serializers.CharField(required=False)
    release_date = serializers.DateTimeField()
    is_released = serializers.BooleanField(default=False)
    
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    completed_at = serializers.DateTimeField(required=False, allow_null=True)
    
    def create(self, validated_data):
        transaction = Transaction(**validated_data)
        transaction.save()
        return transaction
    
    def update(self, instance, validated_data):
        for field, value in validated_data.items():
            setattr(instance, field, value)
        instance.save()
        return instance


class PayoutSerializer(serializers.Serializer):
    """Serializer for Payout model"""
    id = serializers.CharField(read_only=True)
    freelancer_id = serializers.CharField()
    amount = serializers.FloatField()
    
    status = serializers.ChoiceField(choices=['pending', 'processing', 'completed', 'failed'])
    payout_method = serializers.ChoiceField(choices=['bank_transfer', 'paypal', 'check'])
    
    bank_account = serializers.CharField(required=False)
    bank_name = serializers.CharField(required=False)
    routing_number = serializers.CharField(required=False)
    
    created_at = serializers.DateTimeField(read_only=True)
    processed_at = serializers.DateTimeField(required=False, allow_null=True)
    
    def create(self, validated_data):
        payout = Payout(**validated_data)
        payout.save()
        return payout
