#!/usr/bin/env bash
# ============================================================================
#  SOC AI — Setup automatique (a executer par le collegue)
#  Cree la base + le schema, installe l'API, ecrit backend/.env.
#  Usage : bash setup.sh
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")"

echo "=============================================="
echo "  Setup SOC — base + API (cote modele)"
echo "=============================================="

# --- 1. Prerequis -----------------------------------------------------------
missing=0
for c in node npm psql createdb; do
  if ! command -v "$c" >/dev/null 2>&1; then echo "  [X] manquant : $c"; missing=1; fi
done
command -v python3 >/dev/null 2>&1 || echo "  [i] python3 absent (optionnel — pour le pipeline d'ingestion)"
if [ "$missing" = 1 ]; then
  echo
  echo "Installe les outils manquants (Node.js, PostgreSQL client) puis relance."
  exit 1
fi
echo "  [ok] prerequis presents"

# --- 2. Parametres (Entree = valeur par defaut) -----------------------------
echo
echo "--- Base de donnees ---"
read -rp "  Nom de la base [soc]: " DB_NAME;  DB_NAME=${DB_NAME:-soc}
read -rp "  Utilisateur DB [${USER}]: " DB_USER; DB_USER=${DB_USER:-$USER}
read -rp "  Mot de passe DB (vide si aucun): " DB_PASS
read -rp "  Hote DB [localhost]: " DB_HOST;  DB_HOST=${DB_HOST:-localhost}
read -rp "  Port DB [5432]: " DB_PORT;       DB_PORT=${DB_PORT:-5432}
echo
echo "--- Ollama (ton modele local) ---"
read -rp "  URL Ollama [http://localhost:11434]: " OLLAMA_URL;  OLLAMA_URL=${OLLAMA_URL:-http://localhost:11434}
read -rp "  Nom du modele [llama3]: " OLLAMA_MODEL;             OLLAMA_MODEL=${OLLAMA_MODEL:-llama3}

if [ -n "$DB_PASS" ]; then DB_AUTH="$DB_USER:$DB_PASS"; else DB_AUTH="$DB_USER"; fi
DATABASE_URL="postgresql://${DB_AUTH}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
export PGPASSWORD="$DB_PASS"
PSQL_CONN=(-h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER")

# --- 3. Creation de la base -------------------------------------------------
echo
echo "[*] Creation de la base '${DB_NAME}' (si absente)…"
if createdb "${PSQL_CONN[@]}" "$DB_NAME" 2>/dev/null; then
  echo "    base creee"
else
  echo "    (deja existante ou non creee — on continue)"
fi

# --- 4. Application du schema ----------------------------------------------
echo "[*] Application de schema.sql…"
if psql "${PSQL_CONN[@]}" -d "$DB_NAME" -v ON_ERROR_STOP=1 -f schema.sql >/dev/null; then
  echo "    schema OK (tables incidents + audit_log)"
else
  echo "  [X] Echec de l'application du schema. Verifie les acces Postgres."
  exit 1
fi

# --- 5. Installation de l'API ----------------------------------------------
echo "[*] Installation des dependances backend (npm install)…"
( cd backend && npm install ) || { echo "  [X] npm install a echoue"; exit 1; }

# --- 6. Ecriture de backend/.env -------------------------------------------
if [ -f backend/.env ]; then
  cp backend/.env "backend/.env.bak.$(date +%s)"
  echo "[i] backend/.env existant sauvegarde (.env.bak.*)"
fi
cat > backend/.env <<EOF
DATABASE_URL=${DATABASE_URL}
OLLAMA_URL=${OLLAMA_URL}
OLLAMA_MODEL=${OLLAMA_MODEL}
PORT=8000
CORS_ORIGIN=*
PFSENSE_URL=
PFSENSE_TOKEN=
THEHIVE_URL=
THEHIVE_TOKEN=
EOF
echo "[*] backend/.env ecrit."

# --- 6b. Pipeline : acces aux alertes Wazuh (machine distante) --------------
echo
echo "--- Pipeline : lecture des alertes Wazuh (souvent sur une AUTRE machine) ---"
read -rp "  Cible SSH Wazuh (user@ip) [vide = configurer plus tard]: " WAZUH_SSH
if [ -n "$WAZUH_SSH" ]; then
  read -rp "  Chemin alerts.json sur Wazuh [/var/ossec/logs/alerts/alerts.json]: " RPATH
  RPATH=${RPATH:-/var/ossec/logs/alerts/alerts.json}
  read -rp "  Port SSH [22]: " SPORT; SPORT=${SPORT:-22}

  cat > pipeline/run.sh <<EOF
#!/usr/bin/env bash
# Lance le pipeline d'ingestion (genere par setup.sh)
export WAZUH_SSH="${WAZUH_SSH}"
export WAZUH_SSH_PORT="${SPORT}"
export ALERTS_FILE="${RPATH}"
export OLLAMA_URL="${OLLAMA_URL}"
export OLLAMA_MODEL="${OLLAMA_MODEL}"
export BACKEND_URL="http://localhost:8000"
exec python3 "\$(dirname "\$0")/ingest_example.py"
EOF
  chmod +x pipeline/run.sh
  echo "  [ok] pipeline/run.sh genere  ->  lancer avec :  bash pipeline/run.sh"

  echo "  [*] Test de la connexion SSH (lecture du fichier)…"
  if ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -p "$SPORT" "$WAZUH_SSH" "test -r '$RPATH' && echo OK" 2>/dev/null | grep -q OK; then
    echo "      [ok] alerts.json lisible via SSH"
  else
    echo "      [!] SSH KO ou fichier illisible. Installe la cle SSH :"
    echo "          ssh-copy-id -p $SPORT $WAZUH_SSH"
    echo "          (l'utilisateur doit pouvoir lire $RPATH)"
  fi
else
  echo "  [i] Pipeline non configure. Tu pourras lancer plus tard avec les variables"
  echo "      WAZUH_SSH / ALERTS_FILE (voir pipeline/ et le README)."
fi

# --- 7. Fin -----------------------------------------------------------------
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "=============================================="
echo "  Setup termine."
echo "=============================================="
echo "  Demarrer l'API :   cd backend && npm start"
echo "  Tester         :   curl http://localhost:8000/health"
if [ -f pipeline/run.sh ]; then
  echo "  Pipeline (reel):   bash pipeline/run.sh        # lit Wazuh via SSH, corrole, ingere"
fi
echo "  Pipeline (test):   cd pipeline && python3 ingest_example.py   # sur l'exemple local"
echo "  A donner a l'equipe (dashboard) : http://${IP:-TON_IP}:8000"
echo

read -rp "Demarrer l'API maintenant ? [o/N]: " GO
if [ "${GO:-N}" = "o" ] || [ "${GO:-N}" = "O" ]; then
  cd backend && npm start
fi
