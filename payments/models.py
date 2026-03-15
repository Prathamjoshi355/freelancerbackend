from mongoengine import Document, StringField, DateTimeField, ReferenceField, FloatField, BooleanField, IntField
from datetime import datetime
from accounts.models import CustomUser
from proposals.models import Proposal


class Transaction(Document):
    """Payment Transaction Model"""
    meta = {
        'collection': 'transactions',
        'indexes': ['client_id', 'freelancer_id', 'status', 'created_at']
    }
    
    # Transaction parties
    client_id = ReferenceField(CustomUser, required=True)
    freelancer_id = ReferenceField(CustomUser, required=True)
    proposal_id = ReferenceField(Proposal, required=True)
    
    # Amount details
    amount = FloatField(required=True)
    fees = FloatField(default=0)  # Platform fees
    net_amount = FloatField()  # Amount paid to freelancer
    
    # Status
    status = StringField(
        choices=['pending', 'completed', 'failed', 'refunded'],
        default='pending'
    )
    
    # Payment method
    payment_method = StringField(choices=['stripe', 'paypal', 'invoice'], default='stripe')
    transaction_id = StringField()  # External payment provider ID
    
    # Metadata
    description = StringField()
    release_date = DateTimeField()  # When payment should be released
    is_released = BooleanField(default=False)
    
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    completed_at = DateTimeField()
    
    def __str__(self):
        return f"Transaction {self.id} - {self.amount} ({self.status})"
    
    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        super().save(*args, **kwargs)


class Payout(Document):
    """Payout to Freelancer Model"""
    meta = {
        'collection': 'payouts',
        'indexes': ['freelancer_id', 'status']
    }
    
    freelancer_id = ReferenceField(CustomUser, required=True)
    amount = FloatField(required=True)
    
    status = StringField(
        choices=['pending', 'processing', 'completed', 'failed'],
        default='pending'
    )
    
    payout_method = StringField(choices=['bank_transfer', 'paypal', 'check'])
    
    # Bank details
    bank_account = StringField()
    bank_name = StringField()
    routing_number = StringField()
    
    created_at = DateTimeField(default=datetime.utcnow)
    processed_at = DateTimeField()
    
    def __str__(self):
        return f"Payout to {self.freelancer_id.email} - {self.amount}"
