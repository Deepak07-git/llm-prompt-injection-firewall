"""Server-only, non-streaming Ollama transport; contains no firewall decisions."""
import httpx
from django.conf import settings


class OllamaError(Exception):
    def __init__(self, message, status=502):
        self.message = message
        self.status = status
        super().__init__(message)


def chat(messages):
    try:
        # Ignore environment HTTP proxies so local prompts stay local.
        with httpx.Client(timeout=settings.OLLAMA_TIMEOUT_SECONDS, trust_env=False) as client:
            response = client.post(settings.OLLAMA_BASE_URL + "/api/chat", json={
                "model": settings.OLLAMA_MODEL, "messages": messages, "stream": False,
            })
        if response.status_code == 404:
            raise OllamaError("The configured Ollama model is not available.")
        response.raise_for_status()
        data = response.json()
        content = data["message"]["content"]
        if data.get("error") or not isinstance(content, str) or not content.strip():
            raise ValueError("Invalid content")
        return content
    except httpx.TimeoutException:
        raise OllamaError("Local AI service timed out.", 504) from None
    except httpx.RequestError:
        raise OllamaError("Local AI service is unavailable.", 503) from None
    except httpx.HTTPStatusError:
        raise OllamaError("Local AI service returned a server error.") from None
    except (ValueError, KeyError, TypeError):
        raise OllamaError("Local AI service returned an invalid response.") from None
