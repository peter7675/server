import os
import json
import re
import time
import boto3
from botocore.exceptions import ClientError

EMAIL_REGEX = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

# Cached secret and TTL to reduce Secrets Manager calls during warm starts
_cached_keys = None
_cached_keys_fetched_at = 0
CACHE_TTL_SECONDS = int(os.getenv("KEYS_CACHE_TTL", "60"))  # default 60s

def _response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        "body": json.dumps(body),
    }

def _get_header(event, header_name):
    headers = event.get("headers") or {}
    for k, v in headers.items():
        if k.lower() == header_name.lower():
            return v
    return None

def _validate_payload(payload):
    errors = []
    if not isinstance(payload, dict):
        errors.append("payload must be a JSON object")
        return errors

    for field in ("receiver_email", "subject", "body_text"):
        if field not in payload:
            errors.append(f"missing required field: {field}")
        elif not isinstance(payload[field], str) or not payload[field].strip():
            errors.append(f"{field} must be a non-empty string")

    receiver = payload.get("receiver_email", "")
    if isinstance(receiver, str) and not EMAIL_REGEX.match(receiver):
        errors.append("receiver_email is not a valid email address")

    return errors

def _fetch_api_keys(secret_name, region):
    """Fetch the JSON secret from Secrets Manager, cache it for a short TTL."""
    global _cached_keys, _cached_keys_fetched_at
    now = time.time()
    if _cached_keys and (now - _cached_keys_fetched_at) < CACHE_TTL_SECONDS:
        return _cached_keys

    client = boto3.client("secretsmanager", region_name=region)
    try:
        resp = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        # Bubble up to caller to map to HTTP codes
        raise

    secret_string = resp.get("SecretString")
    if not secret_string:
        raise RuntimeError("Secret has no SecretString")

    try:
        data = json.loads(secret_string)
    except json.JSONDecodeError:
        raise RuntimeError("SecretString is not valid JSON")

    keys = data.get("keys", [])
    _cached_keys = keys
    _cached_keys_fetched_at = now
    return keys

def _is_key_valid(provided_key, keys):
    if not provided_key:
        return False
    for entry in keys:
        if not entry.get("active", True):
            continue
        if entry.get("key") == provided_key:
            return True
    return False

def _send_via_ses(from_addr, to_addr, subject, body_text, region):
    client = boto3.client("ses", region_name=region)
    try:
        resp = client.send_email(
            Source=from_addr,
            Destination={"ToAddresses": [to_addr]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {"Text": {"Data": body_text, "Charset": "UTF-8"}},
            },
        )
        return resp
    except ClientError:
        raise

def send_email(event, context):
    """
    Lambda handler for POST /send-email
    Expects JSON body: { "receiver_email": "...", "subject": "...", "body_text": "..." }
    Auth: header 'x-api-key' must match one active key stored in the Secrets Manager secret.
    """
    try:
        secret_name = os.getenv("API_SECRET_NAME")
        if not secret_name:
            return _response(500, {"error": "server_configuration", "message": "API_SECRET_NAME not configured"})

        aws_region = os.getenv("AWS_REGION", "us-east-1")

        provided_api_key = _get_header(event, "x-api-key")
        try:
            keys = _fetch_api_keys(secret_name, aws_region)
        except ClientError as e:
            return _response(500, {"error": "secrets_fetch_failed", "message": str(e)})
        except Exception as e:
            return _response(500, {"error": "invalid_secret", "message": str(e)})

        if not _is_key_valid(provided_api_key, keys):
            return _response(401, {"error": "unauthorized", "message": "Invalid or missing API key"})

        body_text = event.get("body", "")
        if not body_text:
            return _response(400, {"error": "bad_request", "message": "Request body is required"})

        try:
            payload = json.loads(body_text)
        except json.JSONDecodeError:
            return _response(400, {"error": "bad_request", "message": "Request body must be valid JSON"})

        errors = _validate_payload(payload)
        if errors:
            return _response(400, {"error": "validation_failed", "details": errors})

        receiver = payload["receiver_email"].strip()
        subject = payload["subject"].strip()
        message_text = payload["body_text"].strip()

        from_email = os.getenv("FROM_EMAIL")
        if not from_email:
            return _response(500, {"error": "server_configuration", "message": "FROM_EMAIL not configured"})

        try:
            resp = _send_via_ses(from_email, receiver, subject, message_text, aws_region)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            msg = e.response.get("Error", {}).get("Message", str(e))
            if code in ("MessageRejected",):
                return _response(400, {"error": "message_rejected", "message": msg})
            elif code in ("AccessDenied", "UnprocessableEntity"):
                return _response(403, {"error": "forbidden", "message": msg})
            else:
                return _response(502, {"error": "ses_error", "message": msg})

        message_id = resp.get("MessageId")
        return _response(200, {"message": "Email sent", "to": receiver, "message_id": message_id})

    except Exception as e:
        return _response(500, {"error": "internal_error", "message": str(e)})
