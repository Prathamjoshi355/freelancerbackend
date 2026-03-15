from rest_framework import viewsets, generics, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Job, JobApplication
from .serializers import JobSerializer, JobApplicationSerializer, JobDetailSerializer
from accounts.models import CustomUser


class JobViewSet(viewsets.ViewSet):
    """ViewSet for Job operations"""
    
    def list(self, request):
        """List all open jobs with filtering"""
        jobs = Job.objects.filter(status='open')
        
        # Filter by category
        category = request.query_params.get('category')
        if category:
            jobs = jobs.filter(category=category)
        
        # Filter by experience level
        experience = request.query_params.get('experience_level')
        if experience:
            jobs = jobs.filter(experience_level=experience)
        
        # Filter by budget range
        min_budget = request.query_params.get('min_budget')
        max_budget = request.query_params.get('max_budget')
        if min_budget:
            jobs = jobs.filter(budget_min__gte=float(min_budget))
        if max_budget:
            jobs = jobs.filter(budget_max__lte=float(max_budget))
        
        serializer = JobDetailSerializer(jobs, many=True)
        return Response(serializer.data)
    
    def create(self, request):
        """Create a new job (Client only)"""
        if request.user.role != 'client':
            return Response(
                {'detail': 'Only clients can post jobs'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = JobSerializer(data=request.data)
        if serializer.is_valid():
            job = Job(
                client_id=request.user,
                **serializer.validated_data
            )
            job.save()
            return Response(
                JobDetailSerializer(job).data,
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def retrieve(self, request, pk=None):
        """Get job details"""
        try:
            job = Job.objects.get(id=pk)
            job.views_count += 1
            job.save()
            serializer = JobDetailSerializer(job)
            return Response(serializer.data)
        except Job.DoesNotExist:
            return Response(
                {'detail': 'Job not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    def update(self, request, pk=None):
        """Update job (Client only)"""
        try:
            job = Job.objects.get(id=pk)
            if job.client_id.id != request.user.id:
                return Response(
                    {'detail': 'You can only update your own jobs'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            serializer = JobSerializer(data=request.data, partial=True)
            if serializer.is_valid():
                for field, value in serializer.validated_data.items():
                    setattr(job, field, value)
                job.save()
                return Response(JobDetailSerializer(job).data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Job.DoesNotExist:
            return Response(
                {'detail': 'Job not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    def destroy(self, request, pk=None):
        """Delete job (Client only)"""
        try:
            job = Job.objects.get(id=pk)
            if job.client_id.id != request.user.id:
                return Response(
                    {'detail': 'You can only delete your own jobs'},
                    status=status.HTTP_403_FORBIDDEN
                )
            job.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Job.DoesNotExist:
            return Response(
                {'detail': 'Job not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=True, methods=['get'], permission_classes=[IsAuthenticated])
    def applications(self, request, pk=None):
        """Get applications for a job"""
        try:
            job = Job.objects.get(id=pk)
            if job.client_id.id != request.user.id:
                return Response(
                    {'detail': 'You can only view applications for your jobs'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            applications = JobApplication.objects.filter(job_id=job)
            serializer = JobApplicationSerializer(applications, many=True)
            return Response(serializer.data)
        except Job.DoesNotExist:
            return Response(
                {'detail': 'Job not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class ApplyJobView(generics.CreateAPIView):
    """Apply to a job"""
    permission_classes = [IsAuthenticated]
    serializer_class = JobApplicationSerializer
    
    def create(self, request, *args, **kwargs):
        if request.user.role != 'freelancer':
            return Response(
                {'detail': 'Only freelancers can apply to jobs'},
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
        
        # Check if already applied
        existing_application = JobApplication.objects.filter(
            job_id=job,
            freelancer_id=request.user
        ).first()
        
        if existing_application:
            return Response(
                {'detail': 'You have already applied to this job'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        application = JobApplication(
            job_id=job,
            freelancer_id=request.user,
            status='pending'
        )
        application.save()
        
        # Update job proposals count
        job.proposals_count += 1
        job.save()
        
        serializer = JobApplicationSerializer(application)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class MyJobsView(generics.ListAPIView):
    """Get jobs posted by the current client"""
    permission_classes = [IsAuthenticated]
    serializer_class = JobDetailSerializer
    
    def get_queryset(self):
        return Job.objects.filter(client_id=self.request.user)


class MyApplicationsView(generics.ListAPIView):
    """Get applications submitted by the current freelancer"""
    permission_classes = [IsAuthenticated]
    serializer_class = JobApplicationSerializer
    
    def get_queryset(self):
        return JobApplication.objects.filter(freelancer_id=self.request.user)
