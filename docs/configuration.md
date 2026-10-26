# Configuration

Source : variables d'environnement et fichier `.env` (par défaut `./.env`, ou `--env-file`). L'environnement l'emporte.
Générer le fichier : `python cli.py configure`. Modèle : `.env.example`.

| Variable | Défaut | Rôle |
|---|---|---|
| `BREACHHOUND_LLM_PROVIDER` | `none` | `none`, `cloud`, `ollama` |
| `BREACHHOUND_CLOUD_PRESET` | `openai` | `openai`, `anthropic`, `openrouter`, `custom` |
| `BREACHHOUND_CLOUD_API_STYLE` / `_ENDPOINT` / `_MODEL` | selon le préréglage | API `openai` ou `anthropic` |
| `BREACHHOUND_CLOUD_API_KEY` | - | Clé API (jamais affichée) |
| `BREACHHOUND_OLLAMA_ENDPOINT` / `_MODEL` | `http://localhost:11434` / `llama3.1` | Ollama |
| `BREACHHOUND_LLM_TIMEOUT` / `_RETRIES` | `60` / `2` | Délai (s) et nouvelles tentatives (erreurs transitoires) |
| `BREACHHOUND_LANGUAGE` | `fr` | Langue des réponses du LLM |
| `BREACHHOUND_BRUTE_FORCE_THRESHOLD` / `_WINDOW` | `5` / `300` | Seuil et fenêtre (s) |
| `BREACHHOUND_CORRELATION_WINDOW` | `3600` | Proximité temporelle des liens (s) |
| `BREACHHOUND_MAX_LINE_LENGTH` / `_MAX_LINES` / `_MAX_FINDINGS` / `_MAX_FILES` | `8192` / `5000000` / `50000` / `200000` | Bornes mémoire/temps |
| `BREACHHOUND_RECENT_DAYS` | `7` | Fenêtre « récemment modifié » |
| `BREACHHOUND_SYSLOG_YEAR` | auto | Année des logs syslog |

Une configuration LLM invalide n'empêche pas l'investigation : l'analyse LLM est ignorée avec un avertissement.
