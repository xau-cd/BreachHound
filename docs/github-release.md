# GitHub release checklist

Checklist interne avant une release publique.

## Code

- [ ] `pytest` passe.
- [ ] `python -m compileall -q breachhound cli.py` passe.
- [ ] Ruff passe.
- [ ] Mypy passe.
- [ ] Aucun secret dans le dépôt.
- [ ] Les fixtures restent synthétiques.

## Documentation

- [ ] README à jour.
- [ ] Commandes vérifiées.
- [ ] Changelog à jour.
- [ ] Limitations documentées.
- [ ] Security policy présente.

## Release

- [ ] Version Python supportée annoncée.
- [ ] Tag de version créé.
- [ ] Notes de release publiées.
- [ ] Archive source vérifiée.
- [ ] Démo/screenshot actualisé.
