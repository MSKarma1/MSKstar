#!/bin/bash
# -------------------------------
#     MSKstar CLI Launcher 
# -------------------------------

if ! command -v python3 &> /dev/null
then
    echo "Python3 n'est pas installé. Installez-le via https://www.python.org/downloads/"
    exit 1
fi

if [ -f "requirements.txt" ]; then
    echo "Installation des dépendances..."
    python3 -m pip install --upgrade pip
    python3 -m pip install -r requirements.txt
else
    echo "requirements.txt non trouvé."
fi

echo "Lancement de MSKstar..."
python3 MSKSTARCLI.py
