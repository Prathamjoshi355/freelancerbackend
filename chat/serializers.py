from rest_framework import serializers

from core.policies import serialize_datetime


class MessageInputSerializer(serializers.Serializer):
    content = serializers.CharField(required=False, allow_blank=True, default="")
    file = serializers.FileField(required=False)

    def validate(self, attrs):
        content = str(attrs.get("content", "") or "").strip()
        file_obj = attrs.get("file")
        if not content and not file_obj:
            raise serializers.ValidationError("Provide message content or an attachment.")
        attrs["content"] = content
        return attrs


def serialize_conversation(conversation):
    return {
        "id": str(conversation.id),
        "contract_id": str(conversation.contract.id),
        "participant_ids": [str(user.id) for user in conversation.participant_ids],
        "created_at": serialize_datetime(conversation.created_at),
        "updated_at": serialize_datetime(conversation.updated_at),
    }


def serialize_message(message, current_user=None):
    """
    Serialize message with smart blocking:
    - If message is BLOCKED and current_user is NOT the sender: Hide content, show generic "blocked" message
    - If message is BLOCKED and current_user IS the sender: Show content with [BLOCKED] label for reference
    - If message is SENT: Show normally
    """
    content = message.content
    attachment_url = message.attachment_url
    attachment_name = message.attachment_name
    
    # If message is blocked and current user is NOT the sender, hide the actual content
    if message.status == "blocked" and current_user and str(message.sender.id) != str(current_user.id):
        content = "[This message was blocked due to contact or payment information]"
        attachment_url = None
        attachment_name = None
    
    # If message is blocked and sender is viewing their own blocked message, add label
    elif message.status == "blocked" and current_user and str(message.sender.id) == str(current_user.id):
        content = f"[BLOCKED] {message.content}"
    
    return {
        "id": str(message.id),
        "conversation_id": str(message.conversation.id),
        "sender_id": str(message.sender.id),
        "content": content,
        "attachment_url": attachment_url,
        "attachment_name": attachment_name,
        "attachment_type": message.attachment_type,
        "attachment_scan_status": message.attachment_scan_status,
        "status": message.status,
        "moderation_flags": message.moderation_flags or [],
        "created_at": serialize_datetime(message.created_at),
    }
