@echo off
:: -------------------------------
:: MSKstar Launcher with requirements
:: -------------------------------

python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Python n'est pas installé ou n'est pas dans le PATH.
    pause
    exit /b 1
)

if exist "%~dp0requirements.txt" (
    echo Installation des dépendances...
    pip install -r "%~dp0requirements.txt"
) else (
    echo requirements.txt non trouvé.
)

echo Lancement de MSKstar...
python "%~dp0MSKSTARCLI.py"

pause

