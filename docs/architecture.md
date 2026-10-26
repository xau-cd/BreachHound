# Architecture

```
CLI -> Investigator -> Detectors -> Evidence -> Correlator -> Timeline -> Risk Engine -> LLM Analysis -> Incident -> Report
```

1. **Découverte** : la cible est parcourue sans suivre les symlinks ; chaque fichier est classé `web`, `auth` ou `other`
   par inspection du contenu (sniffing des 50-200 premières lignes). Le SHA-256 de chaque log source est enregistré.
2. **Détecteurs** (déterministes, streaming) : `WebAnalyzer`, `AuthAnalyzer`, `ArtifactChecker` produisent des `Finding`
   avec `Evidence` (fichier, ligne, extrait assaini).
3. **Corrélateur** : union-find sur les liens `same_ip` (fenêtre temporelle), `same_file` (chemin de requête <-> chemin
   d'artefact), `same_user`, `temporal_proximity` (faible, uniquement pour les findings sans IP, vers l'ancre précédente).
   Un groupe contenant un finding >= MEDIUM devient un `Incident` (chaîne : stages, vecteur probable, hypothèses de corrélation).
4. **Timeline** : tri chronologique, fusion des répétitions (même IP/catégorie dans les 60 s).
5. **Risk Engine** : score 0-100 documenté dans `breachhound/engine/risk.py`, indépendant du LLM.
6. **LLM** : `LLMProvider` (abstraction) -> `CloudProvider` / `OllamaProvider`. Réponse JSON validée ; les hypothèses sans
   `supporting_finding_ids` valides sont marquées `unsupported`. Toute erreur devient `LLMAnalysis(status="failed")`.
7. **Rapport** : un seul dictionnaire (`build_report`) rendu en Markdown (Jinja2) et JSON.

Niveaux de confiance : chaque finding a une confiance 0-1 (`LOW < 0.45 <= MEDIUM < 0.75 <= HIGH`), chaque incident aussi
(réduite si seuls des liens faibles existent), plus la confiance globale du risque.

Modèles : dataclasses typées (`breachhound/core/models.py`), sérialisables en JSON.
