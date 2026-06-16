# SOC AI — Dossier à installer (côté modèle + base)

Ce dossier contient **tout le côté serveur** du projet SOC : la base de données, l'API qui y accède
et qui parle à Ollama, et le prompt système du modèle. Tu n'as qu'à **brancher ton Ollama local**
et lancer.

```
livraison-collegue/
├── setup.sh                 Installation automatique (à lancer en premier)
├── schema.sql               La base (structure à créer)
├── model_system_prompt.md   Le prompt système à donner à ton modèle Ollama
├── backend/                 L'API (accès DB + Ollama)
│   ├── server.js  db.js  package.json
│   └── .env.example
└── pipeline/                Exemple de pipeline d'ingestion
    ├── ingest_example.py    Wazuh → Ollama → POST /incidents
    └── sample_alerts.json   alertes Wazuh d'exemple (pour tester)
```

## Topologie (important)

Ce backend tourne **sur ta machine**, à côté de Postgres et d'Ollama. Il y accède en `localhost`.
Le dashboard de l'analyste (autre machine) ne touche jamais directement à la DB ni à Ollama : il
passe par **l'API de ce backend**, sur le port **8000**.

```
   TA MACHINE                                  Machine analyste
 ┌──────────────────────────────┐            ┌────────────────────────┐
 │ Postgres → localhost:5432     │            │ Dashboard (navigateur) │
 │ Ollama   → localhost:11434    │            │  → http://TON_IP:8000  │
 │ Backend  → 0.0.0.0:8000 ◄─────┼─── LAN ────┤                        │
 └──────────────────────────────┘            └────────────────────────┘
```

Seul le port **8000** doit être joignable sur le réseau. 5432 et 11434 restent en localhost.

## Installation rapide (recommandé)

Un script fait tout (base + schéma + dépendances + `.env`) :

```bash
cd livraison-collegue
bash setup.sh
```
Il te pose quelques questions (nom de base, accès Postgres, **URL + nom de ton modèle Ollama**),
crée la base, applique `schema.sql`, installe l'API et écrit `backend/.env`. À la fin il propose
de démarrer l'API. C'est tout — passe ensuite à l'étape 3 (brancher le pipeline).

> Prérequis : Node.js + npm, le client PostgreSQL (`psql`, `createdb`), et `python3` (pour le pipeline).

---

## Installation manuelle (pas à pas)

### 1. Créer la base
```bash
createdb soc                       # ou via ton outil Postgres habituel
psql -d soc -f schema.sql          # crée les tables (incidents + audit_log), base vide
```

### 2. Configurer et lancer l'API
```bash
cd backend
npm install
cp .env.example .env
```
Édite `.env` :
- `DATABASE_URL` → ta base (`...@localhost:5432/soc`)
- `OLLAMA_URL` → **ton Ollama** (ex `http://localhost:11434`)
- `OLLAMA_MODEL` → **le nom de ton modèle** (ex `llama3`)

Puis :
```bash
npm start                          # API sur http://localhost:8000
curl http://localhost:8000/health  # doit répondre {"ok":true,"db":true}
```

### 3. Brancher ton pipeline (Wazuh → Ollama → base)

**Important : ce n'est PAS le modèle qui écrit en base.** Ollama renvoie juste le JSON quand on
l'interroge. C'est un *pipeline* (script d'orchestration) qui enchaîne les étapes.

**But = productivité de l'analyste : le dashboard montre des INCIDENTS, pas des alertes brutes.**
1000 alertes Wazuh ne doivent PAS faire 1000 incidents — sinon l'IA ne sert à rien. Le pipeline
**corrèle** : il regroupe les alertes par clé (même IP source + même hôte) sur une fenêtre de
temps, et chaque groupe devient **un seul incident** qualifié par le modèle (qui peut aussi le
marquer `false_positive` si c'est du bruit).

```
Wazuh (alerts.json) → [pipeline: accumule + CORRÈLE] → Ollama (qualifie 1 groupe = 1 incident)
                    → POST /incidents → base    (beaucoup d'alertes → peu d'incidents)
```

La source des alertes = le fichier **`/var/ossec/logs/alerts/alerts.json`** (une alerte JSON par
ligne), sur le **Wazuh manager**. Réglages : `FLUSH_SECONDS` (fenêtre de corrélation), `MIN_LEVEL`
(ignorer le bruit sous ce niveau Wazuh), `MAX_BUFFER`.

#### Wazuh est sur une autre machine → lecture par SSH (recommandé)

Tout (Postgres, Ollama, backend, pipeline) est sur ta machine ; **Wazuh est ailleurs**. Le pipeline
lit alors `alerts.json` **à distance par SSH** (`tail -F` en continu). Il faut une **clé SSH** vers
la machine Wazuh :

```bash
ssh-copy-id -p 22 wazuh@IP_WAZUH        # une fois : autorise la connexion par clé
```

`setup.sh` te configure tout ça et génère `pipeline/run.sh`. Sinon, manuellement :
```bash
WAZUH_SSH="wazuh@IP_WAZUH" \
ALERTS_FILE="/var/ossec/logs/alerts/alerts.json" \
OLLAMA_URL="http://localhost:11434" OLLAMA_MODEL="tonmodele" \
BACKEND_URL="http://localhost:8000" \
  python3 pipeline/ingest_example.py
```
Quand `WAZUH_SSH` est défini, le script passe automatiquement en mode SSH (flux temps réel,
reconnexion auto). L'utilisateur SSH doit pouvoir **lire** `alerts.json` (groupe `ossec` au besoin).

> **Alternative (non incluse)** : interroger le **Wazuh Indexer** (OpenSearch) en HTTP sur
> `https://IP_WAZUH:9200` (index `wazuh-alerts-*`, avec identifiants + TLS). Plus « propre » en
> production, mais plus lourd à configurer (auth, certificat) — le SSH est plus simple pour démarrer.

Un **exemple prêt à adapter** est fourni dans `pipeline/` :
```bash
cd pipeline
# test immédiat sur les alertes d'exemple (sans vrai Wazuh) :
BACKEND_URL=http://localhost:8000 OLLAMA_URL=http://localhost:11434 OLLAMA_MODEL=llama3 \
  python3 ingest_example.py

# en réel, sur le Wazuh manager (suit le fichier en continu) :
ALERTS_FILE=/var/ossec/logs/alerts/alerts.json \
BACKEND_URL=http://localhost:8000 OLLAMA_URL=http://localhost:11434 OLLAMA_MODEL=tonmodele \
  python3 ingest_example.py --follow
```
Le script extrait les champs utiles de chaque alerte, envoie des lots de `BATCH_SIZE` (def. 3) à
Ollama, puis fait le `POST /incidents`. Tu peux aussi écrire directement en base si tu préfères ;
le endpoint évite juste de réécrire le SQL.

Vérifier ensuite : `curl http://localhost:8000/incidents` → les incidents apparaissent.

> Envoi manuel d'un incident (sans pipeline), pour tester le endpoint :
> ```bash
> curl -X POST http://localhost:8000/incidents -H "Content-Type: application/json" \
>   -d '{"incident_id":"INC-TEST-1","is_attack":true,"attack_type":"Brute Force SSH",
>        "confidence":0.9,"summary":"test","score_wazuh":5,"score_ia":8,"score_final":7,
>        "recommended_action":"escalate","mitre_techniques":["T1110.001"],"source_ip":"10.0.0.5",
>        "target_user":"fakeuser","target_host":"ubuntu-virtual-machine","affected_service":"SSH",
>        "priority":"HIGH","batch_size":3,"raw_alerts":[]}'
> ```

### 4. Donner l'accès à l'équipe
Communique **l'IP de ta machine** à l'analyste. Dans le dashboard (page « Connexions »), il met
`http://TON_IP:8000` comme Backend URL et bascule en « Mode réel ». Vérifie que le port 8000 est
ouvert sur le LAN (pare-feu local au besoin).

## Endpoints de l'API

| Méthode + route        | Rôle                                                        |
|------------------------|-------------------------------------------------------------|
| `GET  /health`         | état (et si la DB est connectée)                            |
| `POST /incidents`      | **ingestion** : écrit le JSON du modèle dans la base        |
| `GET  /incidents`      | lecture (consommée par le dashboard)                        |
| `POST /model/ask`      | interroge Ollama (`{OLLAMA_URL}/api/generate`)              |
| `POST /pfsense/block`  | blocage d'IP (optionnel — si tu gères pfSense)              |
| `POST /thehive/case`   | création de case (optionnel)                                |
| `POST /decision`       | persiste une décision analyste (status + audit_log)         |

## Notes
- **Mode résilient** : si une URL d'outil est absente, l'endpoint simule au lieu de planter
  (sauf `GET /incidents` qui exige `DATABASE_URL`).
- `mitre_techniques` et `raw_alerts` sont stockés en `jsonb`.
- Les champs de suivi (`status`, `analyst_action`, `thehive_case_id`, …) sont gérés par la DB /
  l'analyste — le modèle ne les produit pas.
