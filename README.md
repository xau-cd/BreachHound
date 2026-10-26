# BreachHound

<p align="center">
  <img src="assets/breachhound-logo.png" alt="BreachHound logo" width="180">
</p>

<p align="center">
  <strong>Autonomous Security Investigation Engine</strong><br>
  Analyze → Correlate → Diagnose → Report
</p>

<p align="center">
  <a href="https://github.com"><img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white"></a>
  <a href="https://github.com"><img alt="Tests" src="https://img.shields.io/badge/tests-131%20passing-2ea44f"></a>
  <a href="https://github.com"><img alt="License" src="https://img.shields.io/badge/license-MIT-black"></a>
</p>

BreachHound est un outil **DFIR/SOC en Python** conçu pour transformer des logs et artefacts de serveur en une investigation structurée : détection déterministe, corrélation, timeline, scoring de risque et rapport exploitable.

> **Principe clé : le LLM n'est jamais la source de vérité.** Les faits proviennent des détecteurs. Le LLM peut interpréter ces résultats, mais ses hypothèses restent séparées des preuves.

## Pourquoi BreachHound ?

Les investigations réelles produisent rapidement beaucoup de signaux : requêtes HTTP suspectes, brute-force SSH, élévations de privilèges, fichiers inattendus et modifications d'artefacts. BreachHound les rassemble dans un même pipeline afin de répondre à trois questions :

1. **Que s'est-il passé ?**
2. **Quelles preuves supportent cette conclusion ?**
3. **Quel est le niveau de risque et quoi vérifier ensuite ?**

## Fonctionnalités

- **Web analyzer** — SQL injection, XSS, path traversal et patterns RCE.
- **Auth analyzer** — brute-force SSH, connexions réussies après rafale et activité sudo.
- **Artifact checker** — web shells, scripts exécutables dans des uploads et intégrité SHA-256.
- **Correlation engine** — rapprochement des findings par IP, temps et artefacts.
- **Timeline** — reconstruction chronologique des événements pertinents.
- **Risk engine** — score indépendant de l'analyse LLM.
- **LLM optional** — fournisseur cloud ou Ollama local.
- **Reports** — Markdown et JSON.
- **CLI professionnelle** — Click + Rich, diagnostics propres et codes retour utilisables en automatisation.
- **Lecture seule** — les cibles d'investigation ne sont pas modifiées.

## Architecture

```text
                         ┌──────────────────┐
                         │       CLI         │
                         │   Click + Rich    │
                         └────────┬─────────┘
                                  │
                         ┌────────▼─────────┐
                         │   Investigator   │
                         └────────┬─────────┘
                                  │
          ┌───────────────────────┼────────────────────────┐
          │                       │                        │
   ┌──────▼──────┐        ┌──────▼──────┐         ┌──────▼──────┐
   │ Web detector│        │ Auth detector│         │  Artifacts  │
   └──────┬──────┘        └──────┬──────┘         └──────┬──────┘
          └───────────────────────┼────────────────────────┘
                                  ▼
                         ┌──────────────────┐
                         │     Evidence     │
                         └────────┬─────────┘
                                  ▼
                         ┌──────────────────┐
                         │    Correlator    │
                         └────────┬─────────┘
                                  ▼
                    ┌─────────────────────────┐
                    │ Timeline + Risk Engine  │
                    └────────────┬────────────┘
                                 │
                       ┌─────────▼─────────┐
                       │ Optional LLM/RCA  │
                       └─────────┬─────────┘
                                 ▼
                       ┌───────────────────┐
                       │ Markdown + JSON   │
                       └───────────────────┘
```

## Installation

### Linux / macOS

```bash
git clone https://github.com/<YOUR-ACCOUNT>/BreachHound.git
cd BreachHound

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-dev.txt

python cli.py doctor --offline
```

### Windows

```powershell
git clone https://github.com/<YOUR-ACCOUNT>/BreachHound.git
cd BreachHound

py -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt
python cli.py doctor --offline
```

### Termux

```bash
pkg update
pkg install python git

git clone https://github.com/<YOUR-ACCOUNT>/BreachHound.git
cd BreachHound

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python cli.py doctor --offline
```

> Remplace `<YOUR-ACCOUNT>` par le compte GitHub qui héberge le projet.

## Première investigation

Le dépôt contient un scénario **100 % synthétique** pour tester le pipeline sans données réelles :

```bash
python cli.py investigate \
  -t examples/sample_investigation \
  --no-llm \
  --reference-time 2026-10-12T18:00:00Z
```

BreachHound produit ensuite un rapport Markdown et un rapport JSON dans `reports/`.

## Configuration LLM

Configuration interactive :

```bash
python cli.py configure
```

Diagnostic :

```bash
python cli.py doctor
```

Ollama local :

```bash
ollama serve
ollama pull llama3.1
python cli.py configure --provider ollama --model llama3.1 --non-interactive
python cli.py doctor
```

Le mode `--no-llm` reste disponible : les détecteurs, la corrélation, le score et les rapports fonctionnent sans LLM.

## CLI

```text
python cli.py --help

python cli.py version
python cli.py doctor --offline
python cli.py configure

python cli.py investigate \
  --target ./logs_compromis \
  --goal "Trouver le vecteur d'intrusion principal"
```

Options utiles :

```text
--format md|json|both
--no-llm
--baseline PATH
--ioc-hashes PATH
--reference-time ISO_DATE
--threshold INTEGER
--window INTEGER
--fail-on none|low|medium|high|critical
--quiet
--verbose
--debug
```

## Exemple de résultat

Le scénario synthétique couvre notamment des patterns de SQL injection, XSS, path traversal, upload exécutable, web shell et activité d'authentification suspecte.

Le rapport distingue explicitement :

- **faits observés** par les détecteurs ;
- **corrélations** établies par le moteur ;
- **hypothèses** ;
- **interprétation LLM**, lorsqu'elle est activée ;
- **limitations** et recommandations.

## Tests

```bash
pip install -r requirements-dev.txt

python -m compileall -q breachhound cli.py
pytest
ruff check .
mypy
```

La suite actuelle comprend des tests unitaires et d'intégration avec fixtures synthétiques.

## Sécurité

BreachHound est un outil **défensif**. Utilisez-le uniquement sur des systèmes, fichiers et journaux que vous êtes autorisé à examiner.

Le projet applique notamment :

- lecture seule de la cible ;
- non-exécution du contenu découvert dans les artefacts ;
- absence de suivi de symlinks selon les protections du moteur ;
- bornage des lectures ;
- masquage de secrets connus dans les extraits ;
- contenu des logs présenté au LLM comme **données non fiables** ;
- séparation entre preuves déterministes et interprétation LLM ;
- `.env` exclu du dépôt.

Consulte [`SECURITY.md`](SECURITY.md) pour le signalement des vulnérabilités.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — architecture interne
- [`docs/detectors.md`](docs/detectors.md) — moteurs de détection
- [`docs/configuration.md`](docs/configuration.md) — Cloud / Ollama
- [`docs/cli.md`](docs/cli.md) — commandes CLI
- [`docs/github-release.md`](docs/github-release.md) — checklist de release
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — contribuer
- [`SECURITY.md`](SECURITY.md) — sécurité
- [`CHANGELOG.md`](CHANGELOG.md) — historique

## Roadmap

- [x] Détection web / auth / artefacts
- [x] Corrélation et timeline
- [x] Risk scoring
- [x] Rapports Markdown / JSON
- [x] Cloud LLM / Ollama
- [x] CLI et tests synthétiques
- [ ] API backend pour une interface web
- [ ] UI BreachHound connectée au moteur
- [ ] Export STIX / autres formats de threat intelligence
- [ ] Connecteurs SIEM / observabilité
- [ ] Packaging et distribution Python améliorés

## Contribuer

Les contributions sont bienvenues. Commence par une issue pour les changements importants, puis ouvre une pull request avec les tests associés.

Voir [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Licence

MIT — voir [`LICENSE`](LICENSE).
