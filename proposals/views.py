from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from core.policies import compute_final_rating, ensure_freelancer_profile_complete, get_completed_job_ratings
from jobs.models import Job
from profiles.models import Profile
from .models import Proposal
from .serializers import ProposalDetailSerializer, ProposalSerializer


class ProposalViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def create(self, request):
        if request.user.role != 'freelancer':
            return Response({'detail': 'Only freelancers can submit proposals'}, status=status.HTTP_403_FORBIDDEN)
        ensure_freelancer_profile_complete(request.user)

        job_id = request.data.get('job_id')
        try:
            job = Job.objects.get(id=job_id)
        except Job.DoesNotExist:
            return Response({'detail': 'Job not found'}, status=status.HTTP_404_NOT_FOUND)

        if job.status != 'open':
            return Response({'detail': 'Bids are only allowed on open jobs'}, status=status.HTTP_400_BAD_REQUEST)

        existing = Proposal.objects.filter(job_id=job, freelancer_id=request.user).first()
        if existing:
            return Response({'detail': 'You have already submitted a proposal for this job'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ProposalSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        proposal = Proposal(job_id=job, freelancer_id=request.user, **serializer.validated_data)
        proposal.status = 'pending'
        proposal.initial_rating = Profile.objects(user_id=request.user).first().initial_rating if Profile.objects(user_id=request.user).first() else 0
        proposal.final_rating = compute_final_rating(proposal.initial_rating, get_completed_job_ratings(request.user))
        proposal.save()
        job.proposals_count += 1
        job.save()
        return Response(ProposalDetailSerializer(proposal).data, status=status.HTTP_201_CREATED)

    def list(self, request):
        if request.user.role == 'client':
            proposals = Proposal.objects.filter(job_id__client_id=request.user)
        else:
            ensure_freelancer_profile_complete(request.user)
            proposals = Proposal.objects.filter(freelancer_id=request.user)
        return Response(ProposalDetailSerializer(proposals, many=True).data)

    def retrieve(self, request, pk=None):
        try:
            proposal = Proposal.objects.get(id=pk)
        except Proposal.DoesNotExist:
            return Response({'detail': 'Proposal not found'}, status=status.HTTP_404_NOT_FOUND)
        if proposal.freelancer_id.id != request.user.id and proposal.job_id.client_id.id != request.user.id:
            return Response({'detail': 'You do not have permission to view this proposal'}, status=status.HTTP_403_FORBIDDEN)
        return Response(ProposalDetailSerializer(proposal).data)

    @action(detail=True, methods=['post'])
    def accept(self, request, pk=None):
        try:
            proposal = Proposal.objects.get(id=pk)
        except Proposal.DoesNotExist:
            return Response({'detail': 'Proposal not found'}, status=status.HTTP_404_NOT_FOUND)
        if proposal.job_id.client_id.id != request.user.id:
            return Response({'detail': 'You can only accept proposals for your jobs'}, status=status.HTTP_403_FORBIDDEN)
        if proposal.job_id.status != 'open':
            return Response({'detail': 'Only open jobs can hire a freelancer'}, status=status.HTTP_400_BAD_REQUEST)

        proposal.status = 'hired'
        proposal.save()
        Proposal.objects.filter(job_id=proposal.job_id).exclude(id=proposal.id).update(status='auto_rejected')
        proposal.job_id.status = 'hired'
        proposal.job_id.save()
        return Response(ProposalDetailSerializer(proposal).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        try:
            proposal = Proposal.objects.get(id=pk)
        except Proposal.DoesNotExist:
            return Response({'detail': 'Proposal not found'}, status=status.HTTP_404_NOT_FOUND)
        if proposal.job_id.client_id.id != request.user.id:
            return Response({'detail': 'You can only reject proposals for your jobs'}, status=status.HTTP_403_FORBIDDEN)
        proposal.status = 'rejected'
        proposal.save()
        return Response(ProposalDetailSerializer(proposal).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def withdraw(self, request, pk=None):
        try:
            proposal = Proposal.objects.get(id=pk)
        except Proposal.DoesNotExist:
            return Response({'detail': 'Proposal not found'}, status=status.HTTP_404_NOT_FOUND)
        if proposal.freelancer_id.id != request.user.id:
            return Response({'detail': 'You can only withdraw your own proposals'}, status=status.HTTP_403_FORBIDDEN)
        if proposal.status == 'hired':
            return Response({'detail': 'Hired proposals cannot be withdrawn'}, status=status.HTTP_400_BAD_REQUEST)
        proposal.status = 'withdrew'
        proposal.save()
        return Response(ProposalDetailSerializer(proposal).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        try:
            proposal = Proposal.objects.get(id=pk)
        except Proposal.DoesNotExist:
            return Response({'detail': 'Proposal not found'}, status=status.HTTP_404_NOT_FOUND)
        if proposal.job_id.client_id.id != request.user.id:
            return Response({'detail': 'Only the client can complete the job'}, status=status.HTTP_403_FORBIDDEN)
        proposal.completed = True
        proposal.job_rating = float(request.data.get('job_rating', 0))
        proposal.final_rating = compute_final_rating(proposal.initial_rating, get_completed_job_ratings(proposal.freelancer_id) + [proposal.job_rating])
        proposal.save()
        proposal.job_id.status = 'completed'
        proposal.job_id.save()

        profile = Profile.objects(user_id=proposal.freelancer_id).first()
        if profile:
            profile.final_rating = proposal.final_rating
            profile.rating = proposal.final_rating
            profile.save()
        return Response(ProposalDetailSerializer(proposal).data, status=status.HTTP_200_OK)
