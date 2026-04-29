from rest_framework import serializers

from core.policies import serialize_datetime


class BidInputSerializer(serializers.Serializer):
    job_id = serializers.CharField()
    bid_amount = serializers.FloatField(min_value=0)
    proposal = serializers.CharField()


def serialize_bid(bid):
    from core.policies import get_or_create_profile
    from profiles.serializers import serialize_profile_summary

    return {
        "id": str(bid.id),
        "job_id": str(bid.job.id),
        "freelancer_id": str(bid.freelancer.id),
        "bid_amount": round(float(bid.bid_amount or 0), 2),
        "proposal": bid.proposal,
        "status": bid.status,
        "freelancer_profile": serialize_profile_summary(get_or_create_profile(bid.freelancer)),
        "created_at": serialize_datetime(bid.created_at),
        "updated_at": serialize_datetime(bid.updated_at),
    }
