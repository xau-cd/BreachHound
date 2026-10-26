# Contributing to BreachHound

Merci de contribuer à BreachHound. Le projet privilégie les changements petits, testables et orientés défense.

## Environnement

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Windows : `.venv\\Scripts\\activate`.

## Avant une PR

```bash
python -m compileall -q breachhound cli.py
pytest
ruff check .
mypy
```

## Principes techniques

- Les détecteurs déterministes sont la source des faits.
- Le LLM ne doit pas inventer de findings ni remplacer les preuves.
- Les cibles d'investigation sont traitées en lecture seule.
- Les logs, URLs et fichiers sont des données non fiables.
- Ne jamais ajouter de secrets, tokens, clés API ou `.env` au dépôt.
- Toute nouvelle détection doit avoir des tests et des fixtures synthétiques.

## Pull requests

Explique le problème, le changement, les tests exécutés et les éventuels impacts de compatibilité.

Pour une vulnérabilité de sécurité, consulte `SECURITY.md` au lieu de publier des détails exploitables dans une issue publique.
