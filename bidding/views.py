from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.policies import (
    ensure_clean_text,
    require_client_ready,
    require_freelancer_ready,
    require_profile_complete,
)
from jobs.models import Contract, Job
from jobs.serializers import serialize_contract
from .models import Bid
from .serializers import BidInputSerializer, serialize_bid


class BidListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        require_profile_complete(request.user)
        if request.user.role == "client":
            job_id = request.query_params.get("job_id")
            jobs = Job.objects(client=request.user)
            if job_id:
                jobs = jobs.filter(id=job_id)
            job_refs = list(jobs)
            bids = Bid.objects(job__in=job_refs).order_by("-created_at")
        else:
            bids = Bid.objects(freelancer=request.user).order_by("-created_at")
        return Response({"results": [serialize_bid(bid) for bid in bids]})

    def post(self, request):
        require_freelancer_ready(request.user)
        serializer = BidInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        job = Job.objects(id=serializer.validated_data["job_id"]).first()
        if job is None:
            return Response({"detail": "Job not found."}, status=status.HTTP_404_NOT_FOUND)
        if job.status != "open":
            return Response({"detail": "Bids are only allowed on open jobs."}, status=status.HTTP_400_BAD_REQUEST)
        if str(job.client.id) == str(request.user.id):
            return Response({"detail": "Clients cannot bid on their own jobs."}, status=status.HTTP_400_BAD_REQUEST)
        if Bid.objects(job=job, freelancer=request.user).first():
            return Response({"detail": "You can only place one bid per job."}, status=status.HTTP_400_BAD_REQUEST)

        ensure_clean_text(request.user, serializer.validated_data["proposal"], "proposal")

        bid = Bid(
            job=job,
            freelancer=request.user,
            bid_amount=serializer.validated_data["bid_amount"],
            proposal=serializer.validated_data["proposal"],
        )
        bid.save()
        job.bid_count = Bid.objects(job=job, status__ne="withdrawn").count()
        job.save()
        return Response({"bid": serialize_bid(bid)}, status=status.HTTP_201_CREATED)


class BidActionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, bid_id, action):
        bid = Bid.objects(id=bid_id).first()
        if bid is None:
            return Response({"detail": "Bid not found."}, status=status.HTTP_404_NOT_FOUND)

        if action == "hire":
            return self._hire(request, bid)
        if action == "reject":
            return self._reject(request, bid)
        if action == "withdraw":
            return self._withdraw(request, bid)
        return Response({"detail": "Unsupported bid action."}, status=status.HTTP_400_BAD_REQUEST)

    def _hire(self, request, bid):
        require_client_ready(request.user)
        if str(bid.job.client.id) != str(request.user.id):
            return Response({"detail": "You can only hire on your own jobs."}, status=status.HTTP_403_FORBIDDEN)
        if bid.job.status != "open":
            return Response({"detail": "This job is no longer open for hiring."}, status=status.HTTP_400_BAD_REQUEST)
        if Contract.objects(job=bid.job).first():
            return Response({"detail": "A contract already exists for this job."}, status=status.HTTP_400_BAD_REQUEST)

        bid.status = "hired"
        bid.save()
        Bid.objects(job=bid.job, id__ne=bid.id, status="pending").update(status="auto_rejected")
        bid.job.status = "closed"
        bid.job.hired_freelancer = bid.freelancer
        bid.job.hired_bid_id = str(bid.id)
        bid.job.bid_count = Bid.objects(job=bid.job, status__ne="withdrawn").count()
        bid.job.save()

        contract = Contract(
            job=bid.job,
            client=bid.job.client,
            freelancer=bid.freelancer,
            bid_id=str(bid.id),
            agreed_amount=bid.bid_amount,
        )
        contract.save()
        return Response({"bid": serialize_bid(bid), "contract": serialize_contract(contract)})

    def _reject(self, request, bid):
        require_client_ready(request.user)
        if str(bid.job.client.id) != str(request.user.id):
            return Response({"detail": "You can only reject bids on your own jobs."}, status=status.HTTP_403_FORBIDDEN)
        if bid.status != "pending":
            return Response({"detail": "Only pending bids can be rejected."}, status=status.HTTP_400_BAD_REQUEST)
        bid.status = "rejected"
        bid.save()
        return Response({"bid": serialize_bid(bid)})

    def _withdraw(self, request, bid):
        require_freelancer_ready(request.user)
        if str(bid.freelancer.id) != str(request.user.id):
            return Response({"detail": "You can only withdraw your own bids."}, status=status.HTTP_403_FORBIDDEN)
        if bid.status != "pending":
            return Response({"detail": "Only pending bids can be withdrawn."}, status=status.HTTP_400_BAD_REQUEST)
        bid.status = "withdrawn"
        bid.save()
        bid.job.bid_count = Bid.objects(job=bid.job, status__ne="withdrawn").count()
        bid.job.save()
        return Response({"bid": serialize_bid(bid)})
