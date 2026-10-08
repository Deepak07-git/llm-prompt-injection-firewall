# Orbit + independent firewall

The firewall and the local AI chatbot live in separate folders and run on separate ports:

| Service | Folder | Local address |
| --- | --- | --- |
| Firewall dashboard and API | `firewall/` | http://127.0.0.1:8000 |
| Orbit local AI chatbot | `chatbot/` | http://127.0.0.1:3000 |
| Local Ollama model | installed separately | http://127.0.0.1:11434 |

Orbit sends a message to the firewall for inspection before it reaches Ollama. It sends every completed model response through the firewall before showing it. The standalone chatbot has its own conversation database and browser session; it does not import the firewall's Python application. Its dedicated API key belongs to a limited analyst service account, and the key stays in the ignored `chatbot/.env` file.

## Run locally

Use Python 3.11 or newer. Ollama must be installed with a chat model such as `phi3` pulled locally.

In one PowerShell window, start the firewall:

```powershell
cd firewall
python manage.py migrate
python manage.py seed_rules
python manage.py import_threatintel
python manage.py setup_orbit_gateway
python manage.py runserver 127.0.0.1:8000
```

In a second window, start Orbit:

```powershell
cd chatbot
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

The firewall setup command above writes a dedicated API key to the ignored `chatbot/.env` file without displaying it. Keep `.env` private. Start the independent chatbot service:

```powershell
python server.py
```

Open http://127.0.0.1:3000. Use the firewall dashboard at http://127.0.0.1:8000.

## Orbit features

- Separate, mobile-friendly chat interface with dark and light themes.
- Private, per-browser conversation history, searchable and deletable from the sidebar.
- Live firewall connection and local-model status; choose among installed Ollama models.
- Streaming status updates while the input and generated reply pass through the firewall.
- Markdown replies, code blocks, copy buttons, keyboard shortcuts, and starter prompts.
- Loopback-only listener by default, per-browser sessions, origin checks, request-size limits, and local conversation storage.

Every completed chat request requires approval from the firewall's `/api/gateway/input/` and `/api/gateway/output/` endpoints. If the firewall is unavailable or rejects either scan, Orbit does not display the model's reply. The Django dashboard remains a separate, authenticated firewall interface; its former chatbot implementation has been removed.

In the firewall dashboard, disabling a detection rule excludes its matched text from both that rule's match and the AI classifier score. Other enabled rules, obfuscation signals, and the output scanner continue to work. The change applies to the scan API and Orbit chatbot gateway immediately after the firewall process reloads.
