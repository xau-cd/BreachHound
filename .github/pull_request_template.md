## Résumé

Décris clairement le changement proposé.

## Type de changement

- [ ] Bug fix
- [ ] Nouvelle fonctionnalité
- [ ] Refactor sans changement de comportement
- [ ] Documentation
- [ ] CI / tooling

## Vérifications

- [ ] `pytest`
- [ ] `python -m compileall -q breachhound cli.py`
- [ ] Aucun secret ou fichier `.env` ajouté
- [ ] Les tests existants restent verts

## Sécurité

- [ ] Le changement reste en lecture seule lorsqu'il concerne une cible d'investigation
- [ ] Aucun comportement offensif ou destructif n'est introduit
- [ ] Les données non fiables ne sont pas traitées comme des instructions
