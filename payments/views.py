from rest_framework import viewsets, generics, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from datetime import datetime, timedelta
from .models import Transaction, Payout
from .serializers import TransactionSerializer, PayoutSerializer
from proposals.models import Proposal


class TransactionViewSet(viewsets.ViewSet):
    """ViewSet for Transaction operations"""
    permission_classes = [IsAuthenticated]
    
    def list(self, request):
        """List transactions"""
        if request.user.role == 'client':
            transactions = Transaction.objects.filter(client_id=request.user)
        else:
            transactions = Transaction.objects.filter(freelancer_id=request.user)
        
        serializer = TransactionSerializer(transactions, many=True)
        return Response(serializer.data)
    
    def retrieve(self, request, pk=None):
        """Get transaction details"""
        try:
            transaction = Transaction.objects.get(id=pk)
            
            if (transaction.client_id.id != request.user.id and 
                transaction.freelancer_id.id != request.user.id):
                return Response(
                    {'detail': 'You do not have permission to view this transaction'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            serializer = TransactionSerializer(transaction)
            return Response(serializer.data)
        except Transaction.DoesNotExist:
            return Response(
                {'detail': 'Transaction not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=False, methods=['post'])
    def create_payment(self, request):
        """Create a payment for an accepted proposal"""
        proposal_id = request.data.get('proposal_id')
        
        try:
            proposal = Proposal.objects.get(id=proposal_id)
        except Proposal.DoesNotExist:
            return Response(
                {'detail': 'Proposal not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if proposal.job_id.client_id.id != request.user.id:
            return Response(
                {'detail': 'You can only create payments for your accepted proposals'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if proposal.status != 'accepted':
            return Response(
                {'detail': 'You can only pay for accepted proposals'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Calculate fees (10% platform fee)
        amount = proposal.proposed_amount
        fees = amount * 0.10
        net_amount = amount - fees
        
        transaction = Transaction(
            client_id=request.user,
            freelancer_id=proposal.freelancer_id,
            proposal_id=proposal,
            amount=amount,
            fees=fees,
            net_amount=net_amount,
            payment_method=request.data.get('payment_method', 'stripe'),
            release_date=datetime.utcnow() + timedelta(days=7),
            status='pending'
        )
        transaction.save()
        
        return Response(
            TransactionSerializer(transaction).data,
            status=status.HTTP_201_CREATED
        )
    
    @action(detail=True, methods=['post'])
    def confirm_payment(self, request, pk=None):
        """Confirm payment completion"""
        try:
            transaction = Transaction.objects.get(id=pk)
            
            if transaction.client_id.id != request.user.id:
                return Response(
                    {'detail': 'You can only confirm your own payments'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            transaction.status = 'completed'
            transaction.completed_at = datetime.utcnow()
            transaction.save()
            
            return Response(
                TransactionSerializer(transaction).data,
                status=status.HTTP_200_OK
            )
        except Transaction.DoesNotExist:
            return Response(
                {'detail': 'Transaction not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=True, methods=['post'])
    def release_payment(self, request, pk=None):
        """Release payment to freelancer (Admin only or after release date)"""
        try:
            transaction = Transaction.objects.get(id=pk)
            
            if (not request.user.is_staff and 
                transaction.client_id.id != request.user.id):
                return Response(
                    {'detail': 'You do not have permission to release this payment'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            if transaction.is_released:
                return Response(
                    {'detail': 'Payment already released'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            transaction.is_released = True
            transaction.save()
            
            return Response(
                TransactionSerializer(transaction).data,
                status=status.HTTP_200_OK
            )
        except Transaction.DoesNotExist:
            return Response(
                {'detail': 'Transaction not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class PayoutViewSet(viewsets.ViewSet):
    """ViewSet for Payout operations"""
    permission_classes = [IsAuthenticated]
    
    def list(self, request):
        """List payouts for freelancer"""
        if request.user.role != 'freelancer':
            return Response(
                {'detail': 'Only freelancers can view payouts'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        payouts = Payout.objects.filter(freelancer_id=request.user)
        serializer = PayoutSerializer(payouts, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def request_payout(self, request):
        """Request a payout"""
        if request.user.role != 'freelancer':
            return Response(
                {'detail': 'Only freelancers can request payouts'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Calculate available balance
        released_transactions = Transaction.objects.filter(
            freelancer_id=request.user,
            is_released=True,
            status='completed'
        )
        
        available_balance = sum(t.net_amount for t in released_transactions)
        
        payout_amount = request.data.get('amount')
        
        if float(payout_amount) > available_balance:
            return Response(
                {'detail': f'Insufficient balance. Available: {available_balance}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        payout = Payout(
            freelancer_id=request.user,
            amount=float(payout_amount),
            payout_method=request.data.get('payout_method'),
            bank_account=request.data.get('bank_account'),
            bank_name=request.data.get('bank_name'),
            routing_number=request.data.get('routing_number'),
            status='pending'
        )
        payout.save()
        
        return Response(
            PayoutSerializer(payout).data,
            status=status.HTTP_201_CREATED
        )
