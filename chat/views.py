from rest_framework import status
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.policies import register_violation, require_profile_complete
from jobs.models import Contract
from .attachments import upload_chat_attachment
from .models import Conversation, Message
from .protection import analyze_chat_payload
from .serializers import MessageInputSerializer, serialize_conversation, serialize_message


def get_contract_for_user(contract_id, user):
    contract = Contract.objects(id=contract_id).first()
    if contract is None:
        return None
    if str(user.id) not in {str(contract.client.id), str(contract.freelancer.id)}:
        return None
    return contract


def get_or_create_conversation(contract):
    conversation = Conversation.objects(contract=contract).first()
    if conversation is None:
        conversation = Conversation(contract=contract, participant_ids=[contract.client, contract.freelancer])
        conversation.save()
    return conversation


class ContractConversationView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, contract_id):
        require_profile_complete(request.user)
        contract = get_contract_for_user(contract_id, request.user)
        if contract is None:
            return Response({"detail": "Conversation not available for this contract."}, status=status.HTTP_404_NOT_FOUND)

        conversation = get_or_create_conversation(contract)
        messages = Message.objects(conversation=conversation).order_by("created_at")
        return Response(
            {
                "conversation": serialize_conversation(conversation),
                "messages": [serialize_message(message, current_user=request.user) for message in messages],
            }
        )


class ChatProtectionAnalyzeView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request):
        require_profile_complete(request.user)
        serializer = MessageInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        analysis = analyze_chat_payload(
            serializer.validated_data["content"],
            serializer.validated_data.get("file"),
        )
        attachment = analysis["attachment"]

        return Response(
            {
                "blocked": analysis["blocked"],
                "message_flags": analysis["message_flags"],
                "attachment_flags": analysis["attachment_flags"],
                "moderation_flags": analysis["moderation_flags"],
                "normalized_text": analysis["analysis_text"],
                "attachment": {
                    "attachment_name": attachment["attachment_name"],
                    "attachment_type": attachment["attachment_type"],
                    "attachment_scan_status": attachment["attachment_scan_status"],
                    "attachment_scan_error": attachment["attachment_scan_error"],
                    "attachment_extracted_text": attachment["attachment_extracted_text"],
                },
            }
        )


class ContractMessageView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get(self, request, contract_id):
        return ContractConversationView().get(request, contract_id)

    def post(self, request, contract_id):
        require_profile_complete(request.user)
        contract = get_contract_for_user(contract_id, request.user)
        if contract is None:
            return Response({"detail": "Conversation not available for this contract."}, status=status.HTTP_404_NOT_FOUND)

        serializer = MessageInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        conversation = get_or_create_conversation(contract)

        file_obj = serializer.validated_data.get("file")
        
        try:
            analysis = analyze_chat_payload(
                serializer.validated_data["content"],
                file_obj,
            )
        except Exception as exc:
            # If analysis times out, still save message without full analysis
            analysis = {
                "content": serializer.validated_data["content"],
                "blocked": False,
                "moderation_flags": [],
                "attachment": {
                    "attachment_name": getattr(file_obj, "name", "") if file_obj else "",
                    "attachment_type": "attachment",
                    "attachment_extracted_text": "",
                    "attachment_scan_status": "skipped",
                    "attachment_scan_error": "Processing timeout",
                },
            }
        
        attachment_payload = analysis["attachment"]

        if analysis["blocked"]:
            blocked = Message(
                conversation=conversation,
                sender=request.user,
                content=analysis["content"] or "Attachment blocked by moderation.",
                status="blocked",
                moderation_flags=analysis["moderation_flags"],
                attachment_name=attachment_payload["attachment_name"],
                attachment_type=attachment_payload["attachment_type"],
                attachment_extracted_text=attachment_payload["attachment_extracted_text"],
                attachment_scan_status=attachment_payload["attachment_scan_status"],
                attachment_scan_error=attachment_payload["attachment_scan_error"],
            )
            blocked.save()
            register_violation(request.user, "Attempted off-platform contact or payment sharing in chat")
            return Response(
                {"detail": "Message blocked due to contact or off-platform payment content.", "message": serialize_message(blocked, current_user=request.user)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if file_obj is not None:
            attachment_payload.update(upload_chat_attachment(file_obj, contract_id))

        message = Message(
            conversation=conversation,
            sender=request.user,
            content=analysis["content"],
            status="sent",
            attachment_url=attachment_payload["attachment_url"],
            attachment_name=attachment_payload["attachment_name"],
            attachment_type=attachment_payload["attachment_type"],
            attachment_extracted_text=attachment_payload["attachment_extracted_text"],
            attachment_scan_status=attachment_payload["attachment_scan_status"],
            attachment_scan_error=attachment_payload["attachment_scan_error"],
        )
        message.save()
        conversation.save()
        return Response({"message": serialize_message(message, current_user=request.user)}, status=status.HTTP_201_CREATED)
