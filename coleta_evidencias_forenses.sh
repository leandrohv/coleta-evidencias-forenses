#!/usr/bin/env bash
# coleta_evidencias_forenses.sh
#
# Coleta de evidências forenses sobre arquivos com base em padrão de nome
# - Lista arquivos com base no padrão de nome
# - Gera metadados e hashes SHA-256
# - Gera manifesto de integridade
# - Gera um CSV de cadeia de custódia (uma linha por arquivo)
# - Coleta informações de hard disk (lsblk)
# - Compacta tudo em .tar.gz
# - Opcional: assina manifesto e bundle com GPG
#
# PARÂMETROS (modo normal):
#   $1 -> CASE_ID       (Nº da tarefa/chamado, ex: TICKET-1234)
#   $2 -> ANALYST       (nome do profissional/analista)
#   $3 -> ENTITY        (nome da entidade/órgão)
#   $4 -> UNIT          (unidade responsável: "Unidade responsável")
#   $5 -> SUPPLIER      (nome do fornecedor: "Fornecedor A")
#   $6 -> CONTRACT      (nº do contrato / processo)
#   $7 -> TARGET_DIRS   (diretórios, ex: "/ /opt /usr /var /srv/app")
#   $8 -> FILE_PATTERN  (padrão de nome, ex: "*log4j*.jar"; default: "*")
#   $9 -> SIGN_KEY      (ID/e-mail da chave GPG p/ assinar, opcional)
#
# MODO ESPECIAL:
#   --install           (auto-instala o script em /usr/local/sbin)

set -euo pipefail

INSTALL_PATH="/usr/local/sbin/coleta_evidencias_forenses.sh"
BASE_DIR="/var/forensics"

# Pequena função para escapar valores de CSV (aspas → aspas duplicadas)
csv_escape() {
  local s="${1:-}"
  s=${s//\"/\"\"}
  printf '"%s"' "$s"
}

# ========= MODO AUTO-INSTALAÇÃO =========
if [ "${1:-}" = "--install" ]; then
  echo "[*] Instalando script em ${INSTALL_PATH}..."
  if [ ! -d "$(dirname "$INSTALL_PATH")" ]; then
    mkdir -p "$(dirname "$INSTALL_PATH")"
  fi

  cp "$0" "$INSTALL_PATH"
  chmod +x "$INSTALL_PATH"

  echo "[OK] Script instalado em: ${INSTALL_PATH}"
  echo "Leia o cabeçalho do script para detalhes de uso."
  exit 0
fi

# ========= CHECAGEM DE DEPENDÊNCIAS =========
REQUIRED_CMDS=(hostname date uname stat find sha256sum tar id cat)
for cmd in "${REQUIRED_CMDS[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[ERRO] Comando obrigatório não encontrado: $cmd" >&2
    exit 1
  fi
done

# ========= PARÂMETROS =========
CASE_ID="${1:-TAREFA_NAO_INFORMADA}"
ANALYST="${2:-ANALISTA_NAO_INFORMADO}"
ENTITY="${3:-ENTIDADE_NAO_INFORMADA}"
UNIT="${4:-UNIDADE_NAO_INFORMADA}"
SUPPLIER="${5:-FORNECEDOR_NAO_INFORMADO}"
CONTRACT="${6:-CONTRATO_NAO_INFORMADO}"
TARGET_DIRS="${7:-/ /opt /usr /var}"
FILE_PATTERN="${8:-*}"
SIGN_KEY_PARAM="${9:-SIGN_KEY_NAO_INFORMADO}"

# Se SIGN_KEY_PARAM for algo diferente do placeholder, usamos para assinar
SIGN_KEY=""
if [ "$SIGN_KEY_PARAM" != "SIGN_KEY_NAO_INFORMADO" ] && [ -n "$SIGN_KEY_PARAM" ]; then
  if ! command -v gpg >/dev/null 2>&1; then
    echo "[AVISO] SIGN_KEY informada, mas 'gpg' não encontrado. Assinatura GPG será ignorada." >&2
  else
    SIGN_KEY="$SIGN_KEY_PARAM"
  fi
fi

# ========= TIMESTAMPS =========
TS_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')   # Para exibir no relatório
TS_FS=$(date -u '+%Y%m%dT%H%M%SZ')        # Para usar em nomes de arquivos/dirs

HOSTNAME_FQDN=$(hostname -f 2>/dev/null || hostname)
USER_EXEC="$(id)"
OS_INFO="$(uname -a)"

# Garante pasta base de evidências
if [ ! -d "$BASE_DIR" ]; then
  mkdir -p "$BASE_DIR"
fi

# Diretório/bundle inclui CASE_ID + SUPPLIER + HOSTNAME + TS_FS
OUTDIR="${BASE_DIR}/${CASE_ID}_${SUPPLIER}_${HOSTNAME_FQDN}_${TS_FS}"
mkdir -p "$OUTDIR"

# Nomes de arquivos incluem SUPPLIER
REPORT="${OUTDIR}/evidencia_arquivos_${SUPPLIER}_${HOSTNAME_FQDN}_${TS_FS}.txt"
HASHES="${OUTDIR}/arquivos_hashes_${SUPPLIER}_${HOSTNAME_FQDN}_${TS_FS}.txt"
MANIFEST="${OUTDIR}/manifest_sha256_${SUPPLIER}_${HOSTNAME_FQDN}_${TS_FS}.txt"
CSV="${OUTDIR}/cadeia_custodia_${SUPPLIER}_${HOSTNAME_FQDN}_${TS_FS}.csv"
DISK_INFO="${OUTDIR}/disk_info_${SUPPLIER}_${HOSTNAME_FQDN}_${TS_FS}.txt"
BUNDLE="${OUTDIR}.tar.gz"

# ========= CABEÇALHO DO RELATÓRIO =========
{
  echo "===================================================="
  echo " RELATÓRIO DE EVIDÊNCIAS FORENSES – COLETA DE ARQUIVOS"
  echo "======================================================"
  echo "Caso/Tarefa........: $CASE_ID"
  echo "Profissional.......: $ANALYST"
  echo "Entidade/Órgão.....: $ENTITY"
  echo "Unidade............: $UNIT"
  echo "Fornecedor.........: $SUPPLIER"
  echo "Contrato/Processo..: $CONTRACT"
  echo "Hostname (FQDN)....: $HOSTNAME_FQDN"
  echo "Data/Hora (UTC)....: $TS_UTC"
  echo "Usuário executor...: $USER_EXEC"
  echo "Sistema operacional: $OS_INFO"
  echo "Diretório de saída.: $OUTDIR"
  echo "Chave GPG (se usada): $SIGN_KEY_PARAM"
  echo "----------------------------------------------------"
  echo "Diretórios analisados: $TARGET_DIRS"
  echo "Padrão de arquivo....: $FILE_PATTERN"
  echo "Critério de busca....: arquivos cujo nome corresponda ao padrão informado"
  echo "----------------------------------------------------"
  echo
  echo "1) ARQUIVOS ENCONTRADOS (COM BASE NO PADRÃO INFORMADO)"
  echo "----------------------------------------------------"
} > "$REPORT"

# ========= INFORMAÇÕES DE DISCO RÍGIDO =========
{
  echo "===================================================="
  echo " INFORMAÇÕES DE DISCO RÍGIDO (lsblk)"
  echo "===================================================="
} > "$DISK_INFO"

if command -v lsblk >/dev/null 2>&1; then
  {
    echo ">> lsblk -b -o NAME,SIZE,TYPE,ROTA  (SIZE em bytes)"
    lsblk -b -o NAME,SIZE,TYPE,ROTA 2>&1 || lsblk -b 2>&1
    echo
    echo ">> lsblk -b -O (detalhado, se suportado, em bytes)"
    lsblk -b -O 2>/dev/null || echo "lsblk -b -O não suportado nesta versão"
  } >> "$DISK_INFO"
else
  echo "Comando 'lsblk' não encontrado; informações de disco não coletadas." >> "$DISK_INFO"
fi

# ========= CSV DE CADEIA DE CUSTÓDIA (HEADER) =========
{
  echo "Caso/Tarefa,Profissional,Entidade/Órgão,Unidade,Fornecedor,Contrato/Processo,Hostname (FQDN),Data/Hora (UTC),Usuário executor,Sistema operacional,Diretório de saída,Chave GPG (se usada),Diretórios analisados,Padrão de arquivo,Critério de busca,Caminho do arquivo,SHA-256"
} > "$CSV"

# ========= BUSCA DE ARQUIVOS =========
echo "[*] Iniciando busca por arquivos contendo padrão '$FILE_PATTERN'..." >&2

find $TARGET_DIRS \
  -xdev -type f -iname "$FILE_PATTERN" 2>/dev/null -print0 |
while IFS= read -r -d '' FILE; do
  {
    echo "-------------------------------------------------"
    echo "Caminho..........: $FILE"
    stat "$FILE" || echo "Falha ao obter stat para $FILE"
  } >> "$REPORT"
done

{
  echo
  echo "----------------------------------------------------"
  echo "2) HASHES CRIPTOGRÁFICOS DOS ARQUIVOS (SHA-256)"
  echo "----------------------------------------------------"
  echo
} >> "$REPORT"

# ========= GERA HASHES DOS ARQUIVOS + LINHAS NO CSV =========
echo "[*] Calculando hashes SHA-256 dos arquivos..." >&2

: > "$HASHES"

find $TARGET_DIRS \
  -xdev -type f -iname "$FILE_PATTERN" 2>/dev/null -print0 |
while IFS= read -r -d '' FILE; do
  SHA256=""
  if [ -r "$FILE" ]; then
    SHA256=$(sha256sum "$FILE" | awk '{print $1}')
    {
      echo "Arquivo: $FILE"
      echo "SHA256 : $SHA256"
      echo "-----------------------------------------------"
    } >> "$HASHES"
  else
    {
      echo "Arquivo: $FILE"
      echo "SHA256 : [NÃO FOI POSSÍVEL LER O ARQUIVO]"
      echo "-----------------------------------------------"
    } >> "$HASHES"
  fi

  # Linha no CSV (uma por arquivo)
  {
    csv_escape "$CASE_ID";        printf ","
    csv_escape "$ANALYST";        printf ","
    csv_escape "$ENTITY";         printf ","
    csv_escape "$UNIT";           printf ","
    csv_escape "$SUPPLIER";       printf ","
    csv_escape "$CONTRACT";       printf ","
    csv_escape "$HOSTNAME_FQDN";  printf ","
    csv_escape "$TS_UTC";         printf ","
    csv_escape "$USER_EXEC";      printf ","
    csv_escape "$OS_INFO";        printf ","
    csv_escape "$OUTDIR";         printf ","
    csv_escape "$SIGN_KEY_PARAM"; printf ","
    csv_escape "$TARGET_DIRS";    printf ","
    csv_escape "$FILE_PATTERN";   printf ","
    csv_escape "arquivos cujo nome corresponda ao padrão informado"; printf ","
    csv_escape "$FILE";           printf ","
    if [ -n "$SHA256" ]; then
      csv_escape "$SHA256"
    else
      csv_escape "N/A"
    fi
    printf "\n"
  } >> "$CSV"

done

{
  echo "Conteúdo do arquivo de hashes: $HASHES"
  echo
  cat "$HASHES"
} >> "$REPORT"

# ========= MANIFESTO DE INTEGRIDADE =========
echo "[*] Gerando manifesto de integridade (SHA-256)..." >&2

(
  cd "$OUTDIR"
  # Inclui REPORT, HASHES, CSV e DISK_INFO no manifesto
  sha256sum \
    "$(basename "$REPORT")" \
    "$(basename "$HASHES")" \
    "$(basename "$CSV")" \
    "$(basename "$DISK_INFO")" > "$MANIFEST"
)

# ========= BUNDLE DAS EVIDÊNCIAS =========
echo "[*] Compactando evidências em: $BUNDLE" >&2
(
  cd "$(dirname "$OUTDIR")"
  tar -czf "$(basename "$BUNDLE")" "$(basename "$OUTDIR")"
)

# ========= ASSINATURA GPG (OPCIONAL) =========
if [ -n "${SIGN_KEY:-}" ]; then
  echo "[*] Assinando manifesto e bundle com GPG (chave: $SIGN_KEY)..." >&2

  gpg --batch --yes --local-user "$SIGN_KEY" \
      --output "${MANIFEST}.asc" --detach-sign "$MANIFEST" \
      || echo "[!] Falha ao assinar manifesto com GPG" >&2

  gpg --batch --yes --local-user "$SIGN_KEY" \
      --output "${BUNDLE}.asc" --detach-sign "$BUNDLE" \
      || echo "[!] Falha ao assinar bundle com GPG" >&2
fi

echo
echo "==================================================="
echo " COLETA CONCLUÍDA"
echo " Diretório de evidências.: $OUTDIR"
echo " Relatório principal.....: $REPORT"
echo " Hashes dos arquivos.....: $HASHES"
echo " Informações de disco....: $DISK_INFO"
echo " Manifesto de integridade: $MANIFEST"
echo " CSV cadeia de custódia..: $CSV"
echo " Bundle compactado.......: $BUNDLE"
if [ -n "${SIGN_KEY:-}" ]; then
  echo " Assinatura manifesto....: ${MANIFEST}.asc"
  echo " Assinatura bundle.......: ${BUNDLE}.asc"
fi
echo "==================================================="
echo
echo "RECOMENDAÇÕES:"
echo "- Mover o .tar.gz e o(s) .asc para mídia somente leitura."
echo "- Registrar o SHA-256 do bundle, do CSV, do arquivo de disco e o fingerprint da chave GPG na cadeia de custódia."
