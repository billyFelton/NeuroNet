#!/usr/bin/env python3
"""
NeuroNet Pipeline Test — Inject a message directly into RabbitMQ
to test the Resolver → Claude Worker flow.

Usage:
    pip install pika
    python test_pipeline.py "What can you help me with?"
    python test_pipeline.py --role security-analyst "Show me recent failed sign-ins"
    python test_pipeline.py --role general-user "What is the weather?"

This simulates what the Slack connector would publish.
"""

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

import pika


def create_test_envelope(text: str, role: str, user_name: str = "Test User") -> dict:
    """Build a MessageEnvelope matching the NeuroKit format."""
    correlation_id = str(uuid.uuid4())
    return {
        "envelope_version": "1.0",
        "message_id": str(uuid.uuid4()),
        "correlation_id": correlation_id,
        "parent_message_id": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "test-cli",
        "message_type": "user.query",
        "reply_to": "test.response",
        "payload": {
            "text": text,
            "channel": "C_TEST_CHANNEL",
            "thread_ts": None,
            "history": [],
        },
        "actor": {
            "user_id": "00000000-0000-0000-0000-000000000001",
            "email": "testuser@company.com",
            "display_name": user_name,
            "source_channel": "test-cli",
            "source_channel_id": "U_TEST",
            "roles": [role],
            "groups": [],
        },
        "authorization": None,
        "ai_interaction": None,
        "audit_trail": [],
    }


def main():
    parser = argparse.ArgumentParser(description="Test the NeuroNet pipeline")
    parser.add_argument("message", help="Message to send through the pipeline")
    parser.add_argument("--role", default="security-analyst",
                        choices=["security-admin", "security-analyst", "it-support", "general-user"],
                        help="RBAC role to simulate (default: security-analyst)")
    parser.add_argument("--user", default="Test User", help="Display name")
    parser.add_argument("--host", default="localhost", help="RabbitMQ host")
    parser.add_argument("--port", default=5672, type=int, help="RabbitMQ port")
    parser.add_argument("--username", default=None, help="RabbitMQ username")
    parser.add_argument("--password", default=None, help="RabbitMQ password")
    parser.add_argument("--vhost", default=None, help="RabbitMQ vhost")
    parser.add_argument("--timeout", default=30, type=int, help="Response timeout in seconds")
    args = parser.parse_args()

    # Read credentials from .env if not provided
    rmq_user = args.username
    rmq_pass = args.password
    rmq_vhost = args.vhost

    env_file = os.path.join(os.path.dirname(__file__), "deploy", ".env")
    if os.path.exists(env_file) and (not rmq_user or not rmq_pass):
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                if key == "RABBITMQ_USERNAME" and not rmq_user:
                    rmq_user = val
                elif key == "RABBITMQ_PASSWORD" and not rmq_pass:
                    rmq_pass = val
                elif key == "RABBITMQ_VHOST" and not rmq_vhost:
                    rmq_vhost = val

    rmq_user = rmq_user or "neuro"
    rmq_pass = rmq_pass or "guest"
    rmq_vhost = rmq_vhost or "/neuro"

    # Connect to RabbitMQ
    print(f"\n🔌 Connecting to RabbitMQ at {args.host}:{args.port}{rmq_vhost}")
    credentials = pika.PlainCredentials(rmq_user, rmq_pass)
    params = pika.ConnectionParameters(
        host=args.host,
        port=args.port,
        virtual_host=rmq_vhost,
        credentials=credentials,
    )

    try:
        connection = pika.BlockingConnection(params)
    except Exception as e:
        print(f"❌ Cannot connect to RabbitMQ: {e}")
        sys.exit(1)

    channel = connection.channel()

    # Ensure the exchange exists (same type NeuroKit uses)
    channel.exchange_declare(
        exchange="neuro.operational",
        exchange_type="topic",
        durable=True,
        passive=True,  # Don't create, just check it exists
    )

    # Declare the response queue to listen for replies
    result = channel.queue_declare(queue="test.response.queue", auto_delete=True)
    response_queue = result.method.queue

    # Bind to the exchange for test responses
    for routing_key in ["test.response", "ai.response", "ai.response.error"]:
        channel.queue_bind(
            exchange="neuro.operational",
            queue=response_queue,
            routing_key=routing_key,
        )

    # Build and send the message
    envelope = create_test_envelope(args.message, args.role, args.user)
    body = json.dumps(envelope)

    print(f"👤 User: {args.user} (role: {args.role})")
    print(f"📨 Sending: \"{args.message}\"")
    print(f"🆔 Correlation: {envelope['correlation_id']}")
    print()

    channel.basic_publish(
        exchange="neuro.operational",
        routing_key="user.query",
        body=body,
        properties=pika.BasicProperties(
            content_type="application/json",
            correlation_id=envelope["correlation_id"],
        ),
    )
    print("✅ Message published to user.query")
    print(f"⏳ Waiting for response (timeout: {args.timeout}s)...")
    print()

    # Wait for response
    response_received = False
    start_time = time.time()

    def on_response(ch, method, properties, body):
        nonlocal response_received
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            print(f"⚠️  Non-JSON response: {body[:200]}")
            return

        msg_type = data.get("message_type", "unknown")
        source = data.get("source", "unknown")

        if msg_type == "ai.response":
            response_received = True
            payload = data.get("payload", {})
            text = payload.get("text", "(empty)")
            usage = payload.get("usage", {})
            model = payload.get("model", "unknown")

            print("=" * 60)
            print(f"🤖 Response from {source} (model: {model})")
            print("=" * 60)
            print()
            print(text)
            print()
            print("-" * 60)
            if usage:
                print(f"📊 Tokens: {usage.get('input_tokens', '?')} in / {usage.get('output_tokens', '?')} out")
                print(f"💰 Cost: ${usage.get('cost_usd', 0):.4f}")
            print()
            ch.stop_consuming()

        elif msg_type == "ai.response.error":
            response_received = True
            payload = data.get("payload", {})
            error = payload.get("error", "Unknown error")
            error_type = payload.get("type", "")
            print(f"🚫 {error_type}: {error}")
            print()
            ch.stop_consuming()

        else:
            print(f"📩 Received {msg_type} from {source}")

    channel.basic_consume(
        queue=response_queue,
        on_message_callback=on_response,
        auto_ack=True,
    )

    # Consume with timeout
    try:
        while not response_received and (time.time() - start_time) < args.timeout:
            connection.process_data_events(time_limit=1)
    except KeyboardInterrupt:
        print("\n⏹  Cancelled")

    if not response_received:
        print("⏰ Timeout — no response received")
        print()
        print("Debugging tips:")
        print("  docker logs neuro-resolver --tail 20")
        print("  docker logs neuro-agent-claude --tail 20")

    connection.close()


if __name__ == "__main__":
    main()
