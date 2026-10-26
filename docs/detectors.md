# Détecteurs

## Web (`detectors/web`)
Formats : Nginx/Apache Common et Combined. Les lignes mal formées sont **quand même analysées en mode brut** (`parse_quality: raw`).
Normalisation avant règles : décodage URL répété (4 passes), entités HTML, `\xHH`, NUL, NFKC, minuscules, `\` -> `/`,
commentaires SQL (`/**/`, `/*!50000*/`), obfuscation `${lower:j}ndi`. Catégories : SQL_INJECTION, XSS, PATH_TRAVERSAL,
REMOTE_CODE_EXECUTION (chaînage shell, wrappers PHP, Shellshock, Log4Shell, Spring4Shell), WEBSHELL_ACCESS, FILE_UPLOAD,
RECON, SCANNER, plus rafales de 4xx. Un finding par ligne et par catégorie (confiance relevée si plusieurs règles concordent).
`metadata.outcome` : `possible_success` (2xx), `rejected` (4xx), `server_error` (5xx) - **jamais une preuve**.

Limites : pas de corps POST ; charges utiles base64/hex imbriquées ; faux positifs possibles sur des paramètres contenant
du SQL/JS légitime (par ex. un site de documentation) ; `SQLI-BOOLEAN` est volontairement de confiance moyenne.

## Auth (`detectors/auth`)
syslog (`auth.log`, `secure`, format ISO rsyslog) : sshd (échecs, succès, utilisateurs invalides, connexions), sudo (commandes,
refus, mauvais mots de passe), création de compte, ajout à un groupe privilégié. Brute-force : `threshold` échecs dans une fenêtre
de `window` secondes par IP (inclusive, configurable), password spraying si >= 3 comptes, succès après rafale (CRITICAL),
rafales de connexions, brute-force lent. Les horodatages sans année/fuseau sont interprétés en UTC (année : `--year` ou date du fichier).

## Artefacts (`detectors/artifacts`)
Lecture seule, symlinks non suivis. Contrôles : exécutable dans un répertoire d'upload, `.htaccess` dans un upload, double extension,
code serveur dans un fichier de données, binaire ELF/PE déguisé, signatures de web shells (score cumulé : 1 signature forte, ou
2 faibles, ou 1 faible + entropie élevée), fichiers cachés suspects, scripts modifiés récemment (par rapport à `--reference-time`),
mtime futur, SUID/SGID, scripts world-writable, IOC SHA-256, intégrité par rapport à une baseline JSON
(`{"files": {"chemin/relatif": "sha256"}}`).
