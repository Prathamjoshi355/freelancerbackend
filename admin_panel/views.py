from datetime import datetime, timedelta
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import CustomUser
from profiles.models import Profile
from skill_tests.models import FreelancerSkill, Skill, SkillTestAttempt
from jobs.models import Job
from bidding.models import Bid


class AdminStatsView(APIView):
    """Get platform statistics for admin dashboard"""
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        # Count users
        total_users = CustomUser.objects.count()
        total_clients = CustomUser.objects(role="client").count()
        total_freelancers = CustomUser.objects(role="freelancer").count()

        # Count profiles
        complete_profiles = Profile.objects(is_complete=True).count()

        # Count jobs
        total_jobs = Job.objects.count()
        open_jobs = Job.objects(status="open").count()
        completed_jobs = Job.objects(status="completed").count()

        # Count bids
        total_bids = Bid.objects.count()
        pending_bids = Bid.objects(status="pending").count()

        # Count skill tests
        total_attempts = SkillTestAttempt.objects.count()
        completed_tests = SkillTestAttempt.objects(status="completed").count()

        # Revenue estimate (mock calculation)
        total_revenue = completed_jobs * 500  # Mock: 500 per completed job

        # Active this month
        one_month_ago = datetime.utcnow() - timedelta(days=30)
        active_this_month = CustomUser.objects(last_login__gte=one_month_ago).count()

        return Response({
            "users": {
                "total": total_users,
                "clients": total_clients,
                "freelancers": total_freelancers,
                "active_this_month": active_this_month,
            },
            "profiles": {
                "total": total_users,
                "completed": complete_profiles,
            },
            "jobs": {
                "total": total_jobs,
                "open": open_jobs,
                "completed": completed_jobs,
            },
            "bids": {
                "total": total_bids,
                "pending": pending_bids,
            },
            "skill_tests": {
                "total_attempts": total_attempts,
                "completed": completed_tests,
                "completion_rate": round((completed_tests / max(total_attempts, 1)) * 100, 2),
            },
            "revenue": {
                "total": total_revenue,
                "monthly_estimate": total_revenue // 12,
            },
        }, status=status.HTTP_200_OK)


class AdminUsersView(APIView):
    """List all users with pagination"""
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        page = int(request.query_params.get("page", 1))
        page_size = int(request.query_params.get("page_size", 20))
        skip = (page - 1) * page_size

        users = CustomUser.objects.skip(skip).limit(page_size)
        total = CustomUser.objects.count()

        results = []
        for user in users:
            profile = Profile.objects(user=user).first()
            results.append({
                "id": str(user.id),
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
                "profile_complete": profile.is_complete if profile else False,
                "created_at": user.created_at.isoformat() if user.created_at else None,
            })

        return Response({
            "results": results,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        }, status=status.HTTP_200_OK)


class AdminJobsView(APIView):
    """List all jobs with pagination"""
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        page = int(request.query_params.get("page", 1))
        page_size = int(request.query_params.get("page_size", 20))
        skip = (page - 1) * page_size

        jobs = Job.objects.skip(skip).limit(page_size)
        total = Job.objects.count()

        results = []
        for job in jobs:
            results.append({
                "id": str(job.id),
                "title": job.title,
                "status": job.status,
                "budget_min": job.budget_min,
                "budget_max": job.budget_max,
                "created_at": job.created_at.isoformat() if job.created_at else None,
            })

        return Response({
            "results": results,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        }, status=status.HTTP_200_OK)


class AdminTransactionsView(APIView):
    """List all completed jobs (as transactions)"""
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        page = int(request.query_params.get("page", 1))
        page_size = int(request.query_params.get("page_size", 20))
        skip = (page - 1) * page_size

        jobs = Job.objects(status="completed").skip(skip).limit(page_size)
        total = Job.objects(status="completed").count()

        results = []
        for job in jobs:
            results.append({
                "id": f"TXN-{str(job.id)[:8]}",
                "job_title": job.title,
                "amount": (job.budget_min + job.budget_max) / 2,  # Mock average
                "status": "Completed",
                "timestamp": job.created_at.isoformat() if job.created_at else None,
            })

        return Response({
            "results": results,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        }, status=status.HTTP_200_OK)


class AdminSkillTestsView(APIView):
    """List skill test attempts"""
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        page = int(request.query_params.get("page", 1))
        page_size = int(request.query_params.get("page_size", 20))
        skip = (page - 1) * page_size

        attempts = SkillTestAttempt.objects.skip(skip).limit(page_size)
        total = SkillTestAttempt.objects.count()

        results = []
        for attempt in attempts:
            results.append({
                "id": str(attempt.id),
                "user_email": attempt.user.email,
                "skill": attempt.skill.name,
                "status": attempt.status,
                "mcq_stars": attempt.mcq_stars,
                "practical_stars": attempt.practical_stars,
                "total_stars": attempt.total_stars,
                "created_at": attempt.created_at.isoformat() if attempt.created_at else None,
            })

        return Response({
            "results": results,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        }, status=status.HTTP_200_OK)
