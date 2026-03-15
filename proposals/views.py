from rest_framework import viewsets, generics, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from .models import Proposal
from .serializers import ProposalSerializer, ProposalDetailSerializer
from jobs.models import Job


class ProposalViewSet(viewsets.ViewSet):
    """ViewSet for Proposal operations"""
    permission_classes = [IsAuthenticated]
    
    def create(self, request):
        """Submit a proposal (Freelancer only)"""
        if request.user.role != 'freelancer':
            return Response(
                {'detail': 'Only freelancers can submit proposals'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        job_id = request.data.get('job_id')
        
        try:
            job = Job.objects.get(id=job_id)
        except Job.DoesNotExist:
            return Response(
                {'detail': 'Job not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if already proposed
        existing = Proposal.objects.filter(
            job_id=job,
            freelancer_id=request.user
        ).first()
        
        if existing:
            return Response(
                {'detail': 'You have already submitted a proposal for this job'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = ProposalSerializer(data=request.data)
        if serializer.is_valid():
            proposal = Proposal(
                job_id=job,
                freelancer_id=request.user,
                **serializer.validated_data
            )
            proposal.save()
            return Response(
                ProposalDetailSerializer(proposal).data,
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def list(self, request):
        """List proposals (filtered by role)"""
        if request.user.role == 'client':
            # Show proposals for client's jobs
            proposals = Proposal.objects.filter(
                job_id__client_id=request.user
            )
        else:
            # Show proposals submitted by freelancer
            proposals = Proposal.objects.filter(freelancer_id=request.user)
        
        serializer = ProposalDetailSerializer(proposals, many=True)
        return Response(serializer.data)
    
    def retrieve(self, request, pk=None):
        """Get proposal details"""
        try:
            proposal = Proposal.objects.get(id=pk)
            
            # Check authorization
            if (proposal.freelancer_id.id != request.user.id and 
                proposal.job_id.client_id.id != request.user.id):
                return Response(
                    {'detail': 'You do not have permission to view this proposal'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            serializer = ProposalDetailSerializer(proposal)
            return Response(serializer.data)
        except Proposal.DoesNotExist:
            return Response(
                {'detail': 'Proposal not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=True, methods=['post'])
    def accept(self, request, pk=None):
        """Accept a proposal (Client only)"""
        try:
            proposal = Proposal.objects.get(id=pk)
            
            if proposal.job_id.client_id.id != request.user.id:
                return Response(
                    {'detail': 'You can only accept proposals for your jobs'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            proposal.status = 'accepted'
            proposal.save()
            
            # Reject other proposals for this job
            Proposal.objects.filter(
                job_id=proposal.job_id,
                status='pending'
            ).exclude(id=proposal.id).update(status='rejected')
            
            # Update job status
            proposal.job_id.status = 'in_progress'
            proposal.job_id.save()
            
            return Response(
                ProposalDetailSerializer(proposal).data,
                status=status.HTTP_200_OK
            )
        except Proposal.DoesNotExist:
            return Response(
                {'detail': 'Proposal not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject a proposal (Client only)"""
        try:
            proposal = Proposal.objects.get(id=pk)
            
            if proposal.job_id.client_id.id != request.user.id:
                return Response(
                    {'detail': 'You can only reject proposals for your jobs'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            proposal.status = 'rejected'
            proposal.save()
            
            return Response(
                ProposalDetailSerializer(proposal).data,
                status=status.HTTP_200_OK
            )
        except Proposal.DoesNotExist:
            return Response(
                {'detail': 'Proposal not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=True, methods=['post'])
    def withdraw(self, request, pk=None):
        """Withdraw a proposal (Freelancer only)"""
        try:
            proposal = Proposal.objects.get(id=pk)
            
            if proposal.freelancer_id.id != request.user.id:
                return Response(
                    {'detail': 'You can only withdraw your own proposals'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            proposal.status = 'withdrew'
            proposal.save()
            
            return Response(
                ProposalDetailSerializer(proposal).data,
                status=status.HTTP_200_OK
            )
        except Proposal.DoesNotExist:
            return Response(
                {'detail': 'Proposal not found'},
                status=status.HTTP_404_NOT_FOUND
            )
