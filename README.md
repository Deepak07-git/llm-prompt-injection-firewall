# Vedappu + independent firewall

The firewall and the local AI chatbot live in separate folders and run on separate ports:

| Service | Folder | Local address |
| --- | --- | --- |
| Firewall dashboard and API | `firewall/` | http://127.0.0.1:8000 |
| Vedappu local AI chatbot | `chatbot/` | http://127.0.0.1:3000 |
| Local Ollama model | installed separately | http://127.0.0.1:11434 |

Vedappu sends a message to the firewall for inspection before it reaches Ollama. It sends every completed model response through the firewall before showing it. The standalone chatbot has its own conversation database and browser session; it does not import the firewall's Python application. Its dedicated API key belongs to a limited analyst service account, and the key stays in the ignored `chatbot/.env` file.

## Run locally

Use Python 3.11 or newer and Node.js 20.19+ or 22.12+. Ollama must be installed with a chat model such as `phi3` pulled locally.

In one PowerShell window, start the firewall:

```powershell
cd firewall
python manage.py migrate
python manage.py seed_rules
python manage.py import_threatintel
python manage.py setup_orbit_gateway
python manage.py runserver 127.0.0.1:8000
```

Build Vedappu's React interface, then start its standalone Python service in a second window:

```powershell
cd chatbot
python -m pip install -r requirements.txt
cd frontend
npm.cmd install
npm.cmd run build
cd ..
```

The firewall setup command above writes a dedicated API key to the ignored `chatbot/.env` file without displaying it. Keep `.env` private and keep that generated file in place. Start the independent chatbot service:

```powershell
python server.py
```

Open http://127.0.0.1:3000. Use the firewall dashboard at http://127.0.0.1:8000.

## Vedappu features

- React, Tailwind CSS, and Lucide interface with dark and light themes.
- Private, per-browser conversation history, searchable and deletable from the sidebar.
- Live firewall connection and local-model status; choose among installed Ollama models.
- Processing status while the input and completed reply pass through the firewall.
- Markdown replies, tables, code blocks, copy and regenerate controls, feedback, keyboard shortcuts, starter prompts, and text attachments.
- Loopback-only listener by default, per-browser sessions, origin checks, request-size limits, and local conversation storage.

Every completed chat request requires approval from the firewall's `/api/gateway/input/` and `/api/gateway/output/` endpoints. If the firewall is unavailable or rejects either scan, Vedappu does not display the model's reply. The Django dashboard remains a separate, authenticated firewall interface; its former chatbot implementation has been removed. The microphone control explains that local voice transcription is not configured; it does not record audio.

In the firewall dashboard, disabling a detection rule excludes its matched text from both that rule's match and the AI classifier score. Other enabled rules, obfuscation signals, and the output scanner continue to work. The change applies to the scan API and Vedappu chatbot gateway immediately after the firewall process reloads.

## Upload a provider's terms as firewall rules

Open **Rules** in the firewall dashboard, enter the AI provider name, and upload a text-based PDF, DOCX, or UTF-8 TXT use policy. The firewall extracts explicit prohibited-use clauses, including bullets under a prohibition heading, and asks local Ollama (`OLLAMA_MODEL=phi3` by default) for candidate action and target phrases. Each candidate must cite a clause grounded in the uploaded text, match its prohibited examples, avoid benign examples, and add blocking coverage beyond the built-in rules. Candidates that fail validation are discarded. Scanned image PDFs need OCR before upload.

The upload opens a preview of source clauses, example prompts, and actual detection patterns. Try your own prompt there, then select and activate the rules you want. You can select the active provider profile from the Rules page. The scan API and Vedappu chatbot gateway use that one profile together with the default prompt-injection rules; switching profiles changes enforcement immediately. Re-uploading an updated policy for the same provider replaces obsolete generated rules while preserving the enabled/disabled state of unchanged patterns. The firewall stores the file hash, source clauses, and reviewed patterns, not the full uploaded document.

Policy text is often broad legal language, so a document may produce no defensible prompt pattern. In that case the upload reports why and leaves the active rules untouched. The model generates candidates locally; the deterministic validator and your preview decide what becomes an active rule. Set `POLICY_OLLAMA_MODEL` and `POLICY_OLLAMA_BASE_URL` if policy extraction should use a different local Ollama model or server.
