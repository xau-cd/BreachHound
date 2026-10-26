# Security Policy

## Périmètre

BreachHound est conçu pour l'analyse défensive de logs et d'artefacts dans des environnements que l'utilisateur est autorisé à examiner.

## Signaler une vulnérabilité

Merci de ne pas publier de secrets, preuves sensibles ou détails d'exploitation dans une issue publique.

Si le dépôt propose les GitHub Security Advisories, utilisez la fonction de signalement privé. Sinon, contactez les mainteneurs via leur profil GitHub avant toute divulgation publique.

Incluez, si possible :

- version concernée ;
- environnement Python/OS ;
- étapes minimales de reproduction ;
- impact observé ;
- correctif ou mitigation proposée, si connue.

Les exemples et fixtures du dépôt doivent rester synthétiques et ne doivent pas contenir de données réelles.

## Principes de sécurité du projet

- Analyse de cible en lecture seule.
- Pas d'exécution de contenu découvert dans les artefacts.
- Validation de configuration avant les appels LLM.
- Secrets exclus du dépôt et des logs.
- Contenu analysé traité comme données non fiables.
- Les conclusions LLM restent séparées des faits déterministes.
