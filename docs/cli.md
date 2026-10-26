# CLI

`python cli.py [--verbose] [--debug] <commande>`

| Commande | Description |
|---|---|
| `configure` | Configuration interactive (ou `--provider/--preset/--endpoint/--model/--api-key --non-interactive`) |
| `investigate` | `--target`, `--goal`, `--output-dir`, `--format`, `--no-llm`, `--baseline`, `--ioc-hashes`, `--reference-time`, `--threshold`, `--window`, `--year`, `--fail-on`, `--quiet` |
| `doctor` | Dépendances, configuration, connexion LLM (`--offline` pour l'ignorer) |
| `version` | Version |

Codes retour : `0` succès, `1` erreur, `2` usage, `3` configuration, `4` cible introuvable, `10` seuil `--fail-on` atteint,
`70` erreur interne (utilisez `--debug` pour la trace).
