from datetime import datetime

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.policies import (
    ensure_clean_text,
    require_client_ready,
    require_profile_complete,
    sync_user_account_status,
    update_freelancer_ratings,
)
from skill_tests.models import Skill
from .models import Contract, Job, Review
from .serializers import (
    ContractCompletionSerializer,
    FreelancerClientFeedbackSerializer,
    JobInputSerializer,
    serialize_contract,
    serialize_job,
    serialize_review,
)


class JobListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        require_profile_complete(request.user)
        q = (request.query_params.get("q") or "").strip().lower()
        skill_filter = (request.query_params.get("skill") or "").strip().lower()
        queryset = Job.objects(status="open").order_by("-created_at")
        results = []
        for job in queryset:
            if skill_filter and skill_filter not in (job.required_skill_slugs or []):
                continue
            search_blob = " ".join(
                [job.title or "", job.description or "", " ".join(job.required_skill_slugs or [])]
            ).lower()
            if q and q not in search_blob:
                continue
            results.append(serialize_job(job))
        return Response({"results": results})

    def post(self, request):
        require_client_ready(request.user)
        serializer = JobInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        ensure_clean_text(request.user, serializer.validated_data["title"], "title")
        ensure_clean_text(request.user, serializer.validated_data["description"], "description")

        skill_slugs = sorted({slug.strip().lower() for slug in serializer.validated_data["required_skill_slugs"] if slug.strip()})
        known_skills = Skill.objects(slug__in=skill_slugs, is_active=True)
        if known_skills.count() != len(skill_slugs):
            return Response({"detail": "Job required skills must come from the predefined skill catalog."}, status=status.HTTP_400_BAD_REQUEST)

        job = Job(client=request.user, **serializer.validated_data)
        job.required_skill_slugs = skill_slugs
        job.save()
        return Response({"job": serialize_job(job)}, status=status.HTTP_201_CREATED)


class MyJobsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        require_client_ready(request.user)
        jobs = Job.objects(client=request.user).order_by("-created_at")
        return Response({"results": [serialize_job(job) for job in jobs]})


class JobDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, job_id):
        return Job.objects(id=job_id).first()

    def get(self, request, job_id):
        require_profile_complete(request.user)
        job = self.get_object(job_id)
        if job is None:
            return Response({"detail": "Job not found."}, status=status.HTTP_404_NOT_FOUND)

        payload = {"job": serialize_job(job)}
        contract = Contract.objects(job=job).first()
        if contract:
            payload["contract"] = serialize_contract(contract)
        return Response(payload)

    def patch(self, request, job_id):
        job = self.get_object(job_id)
        if job is None:
            return Response({"detail": "Job not found."}, status=status.HTTP_404_NOT_FOUND)
        if str(job.client.id) != str(request.user.id):
            return Response({"detail": "You can only edit your own jobs."}, status=status.HTTP_403_FORBIDDEN)
        if job.status != "open":
            return Response({"detail": "Only open jobs can be edited."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = JobInputSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        for field, value in serializer.validated_data.items():
            if field in {"title", "description"}:
                ensure_clean_text(request.user, value, field)
            if field == "required_skill_slugs":
                value = sorted({slug.strip().lower() for slug in value if slug.strip()})
            setattr(job, field, value)
        job.save()
        return Response({"job": serialize_job(job)})


class ContractListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        require_profile_complete(request.user)
        if request.user.role == "client":
            contracts = Contract.objects(client=request.user).order_by("-created_at")
        else:
            contracts = Contract.objects(freelancer=request.user).order_by("-created_at")
        return Response({"results": [serialize_contract(contract) for contract in contracts]})


class ContractDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, contract_id):
        require_profile_complete(request.user)
        contract = Contract.objects(id=contract_id).first()
        if contract is None:
            return Response({"detail": "Contract not found."}, status=status.HTTP_404_NOT_FOUND)
        if str(request.user.id) not in {str(contract.client.id), str(contract.freelancer.id)}:
            return Response({"detail": "You do not have access to this contract."}, status=status.HTTP_403_FORBIDDEN)

        review = Review.objects(contract=contract).first()
        payload = {"contract": serialize_contract(contract), "job": serialize_job(contract.job)}
        if review:
            payload["review"] = serialize_review(review)
        return Response(payload)


class ContractCompleteView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, contract_id):
        contract = Contract.objects(id=contract_id).first()
        if contract is None:
            return Response({"detail": "Contract not found."}, status=status.HTTP_404_NOT_FOUND)
        if str(contract.client.id) != str(request.user.id):
            return Response({"detail": "Only the client can complete a contract."}, status=status.HTTP_403_FORBIDDEN)

        from payments.models import Payment

        payment = Payment.objects(contract=contract, status="verified").first()
        if payment is None:
            return Response({"detail": "Payment must be completed inside the platform before review."}, status=status.HTTP_400_BAD_REQUEST)
        if Review.objects(contract=contract).first():
            return Response({"detail": "This contract has already been reviewed."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ContractCompletionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        review = Review(
            contract=contract,
            job=contract.job,
            client=contract.client,
            freelancer=contract.freelancer,
            rating=serializer.validated_data["rating"],
            comment=serializer.validated_data.get("comment", ""),
        )
        review.save()

        contract.status = "completed"
        contract.completed_at = datetime.utcnow()
        contract.save()
        contract.job.status = "completed"
        contract.job.save()

        ratings = update_freelancer_ratings(contract.freelancer)
        sync_user_account_status(contract.freelancer)
        return Response({"contract": serialize_contract(contract), "review": serialize_review(review), "ratings": ratings})


class ContractClientFeedbackView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, contract_id):
        contract = Contract.objects(id=contract_id).first()
        if contract is None:
            return Response({"detail": "Contract not found."}, status=status.HTTP_404_NOT_FOUND)
        if str(contract.freelancer.id) != str(request.user.id):
            return Response({"detail": "Only the hired freelancer can review this client."}, status=status.HTTP_403_FORBIDDEN)
        if contract.status != "completed":
            return Response({"detail": "Client feedback is available after contract completion."}, status=status.HTTP_400_BAD_REQUEST)

        review = Review.objects(contract=contract).first()
        if review is None:
            return Response({"detail": "Client must submit the final project review first."}, status=status.HTTP_400_BAD_REQUEST)
        if review.client_rating:
            return Response({"detail": "Client feedback has already been submitted."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = FreelancerClientFeedbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        ensure_clean_text(
            request.user,
            serializer.validated_data.get("client_comment", ""),
            "client_comment",
        )

        review.client_rating = serializer.validated_data["client_rating"]
        review.client_comment = serializer.validated_data.get("client_comment", "")
        review.client_reviewed_at = datetime.utcnow()
        review.save()

        return Response({"contract": serialize_contract(contract), "review": serialize_review(review)})
