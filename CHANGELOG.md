# Changelog

Toutes les modifications importantes de BreachHound sont documentées ici.

## [1.0.0] - 2026-10-25

### Added

- Analyse déterministe des logs web et authentification.
- Détection d'artefacts et de web shells suspects.
- Corrélation des findings et construction de timeline.
- Risk scoring indépendant du LLM.
- Analyse LLM optionnelle via fournisseur cloud ou Ollama.
- Rapports Markdown et JSON.
- CLI Click/Rich avec `configure`, `doctor`, `investigate` et `version`.
- Fixtures et scénario synthétique d'investigation.
- Tests unitaires et d'intégration.
- CI GitHub Actions pour tests multi-versions Python.
