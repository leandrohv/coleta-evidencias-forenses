# Coleta de Evidências Forenses de Arquivos em Sistemas Linux

Script: `coleta_evidencias_forenses.sh`  
Local sugerido de instalação: `/usr/local/sbin/coleta_evidencias_forenses.sh`  
Plataforma: Linux (Ubuntu, Debian, Red Hat, Oracle Linux, SUSE, etc.)

---

## 1. Objetivo

Estabelecer um procedimento padronizado para **coleta de evidências forenses de arquivos** em sistemas Linux, com foco em:

- Listagem de arquivos com base em um **padrão de nome** (ex.: `*log4j*.jar`).
- Geração de **metadados** dos arquivos (via `stat`).
- Geração de **hashes SHA-256** dos arquivos encontrados.
- Geração de **manifesto de integridade** dos artefatos produzidos.
- Geração de **CSV de cadeia de custódia**, com **uma linha por arquivo** evidenciado.
- Coleta de **informações de disco rígido** (via `lsblk` em bytes).
- Compactação das evidências em um **bundle `.tar.gz`**, com assinatura opcional via **GPG**.

> ⚠️ Este script não substitui procedimentos de *full disk imaging* ou coleta de memória.  
> Ele é complementar para evidências em nível de **arquivos**.

---

## 2. Escopo

Aplica-se a:

- Servidores Linux sob responsabilidade de TI / Segurança / Forense.
- Atividades de **resposta a incidentes** e **investigações forenses**.
- Cenários onde é necessário **comprovar a existência** (ou ausência) de arquivos específicos e a integridade dos dados coletados.

---

## 3. Pré-requisitos

### 3.1 Dependências

Os seguintes comandos devem estar disponíveis:

- `hostname`
- `date`
- `uname`
- `stat`
- `find`
- `sha256sum`
- `tar`
- `id`
- `cat`
- `lsblk`
- (Opcional) `gpg` – para assinatura GPG do manifesto e do bundle.

### 3.2 Permissões

- Recomenda-se executar como `root` ou via `sudo`, principalmente se os diretórios alvo incluírem `/`, `/var`, `/opt`, `/usr` etc.
- A pasta base de evidências deve ser acessível:

```text
/var/forensics
```

A cada execução é criado um subdiretório com o padrão:

```text
CASE_ID_SUPPLIER_HOSTNAME_YYYYMMDDTHHMMSSZ/
```

---

## 4. Instalação

1. Salve o script como `coleta_evidencias_forenses.sh`.
2. Torne o script executável:

```bash
chmod +x coleta_evidencias_forenses.sh
```

3. (Opcional, recomendado) Instale em `/usr/local/sbin`:

```bash
sudo ./coleta_evidencias_forenses.sh --install
```

4. Após instalado:

```bash
sudo /usr/local/sbin/coleta_evidencias_forenses.sh ...
```

---

## 5. Parâmetros do Script

O script utiliza **9 parâmetros posicionais**, nesta ordem:

| Ordem | Nome         | Descrição                                                                                 | Exemplo                                          | Obrigatório | Default                         |
|-------|--------------|-------------------------------------------------------------------------------------------|--------------------------------------------------|------------|---------------------------------|
| `$1`  | `CASE_ID`    | Identificador do caso/tarefa/chamado.                                                     | `"TAREFA-LOG4J-1234"`                            | Sim        | `TAREFA_NAO_INFORMADA`         |
| `$2`  | `ANALYST`    | Nome do profissional/analista responsável.                                               | `"Nome do Profissional"`             | Sim        | `ANALISTA_NAO_INFORMADO`       |
| `$3`  | `ENTITY`     | Nome da entidade/órgão.                                                                  | `"Entidade"`            | Sim        | `ENTIDADE_NAO_INFORMADA`       |
| `$4`  | `UNIT`       | Unidade responsável.                                                               | `"Unidade Responsável"`                                   | Sim        | `UNIDADE_NAO_INFORMADA`        |
| `$5`  | `SUPPLIER`   | Fornecedor/sistema sob análise.                                                          | `"Fornecedor A"`, `"Fornecedor B"`                       | Sim        | `FORNECEDOR_NAO_INFORMADO`     |
| `$6`  | `CONTRACT`   | Número do contrato ou processo relacionado.                                              | `"Contrato 123/2025"`                            | Sim        | `CONTRATO_NAO_INFORMADO`       |
| `$7`  | `TARGET_DIRS`| Diretórios alvo da busca.                                                                | `"/"`, `"/ /opt /usr /var /srv/app"`             | Sim        | `/ /opt /usr /var`             |
| `$8`  | `FILE_PATTERN`| Padrão de nome de arquivo (glob, case-insensitive).                                     | `"*log4j*.jar"`                                  | Não        | `*` (todos os arquivos)        |
| `$9`  | `SIGN_KEY`   | ID/e-mail da chave GPG para assinar manifesto e bundle (opcional).                       | `"nome.sobrenome@domínio.com.br"`                       | Não        | `SIGN_KEY_NAO_INFORMADO`       |

> ℹ️ Se `SIGN_KEY` for informado, a assinatura só será feita se:
> - `gpg` existir no sistema; e  
> - a chave correspondente estiver no keyring do usuário executor.

---

## 6. Artefatos Gerados

Para cada execução, é criado um diretório em `/var/forensics`:

```text
/var/forensics/CASE_ID_SUPPLIER_HOSTNAME_YYYYMMDDTHHMMSSZ/
```

Dentro dele, no mínimo:

1. **Relatório principal (texto)**  
   Arquivo:  
   `evidencia_arquivos_SUPPLIER_HOSTNAME_TIMESTAMP.txt`  

   Contém:
   - Cabeçalho (caso, analista, entidade, unidade, fornecedor, contrato).
   - Contexto do host (hostname, SO, usuário).
   - Diretórios analisados, padrão de arquivo, critério de busca.
   - Lista de arquivos encontrados (`stat` por arquivo).

2. **Hashes dos arquivos (SHA-256)**  
   Arquivo:  
   `arquivos_hashes_SUPPLIER_HOSTNAME_TIMESTAMP.txt`  

   Contém:
   - `SHA-256` de cada arquivo encontrado (ou mensagem de erro de leitura).

3. **CSV da cadeia de custódia (uma linha por arquivo)**  
   Arquivo:  
   `cadeia_custodia_SUPPLIER_HOSTNAME_TIMESTAMP.csv`  

   Cada linha contém:

   - Caso/Tarefa  
   - Profissional  
   - Entidade/Órgão  
   - Unidade  
   - Fornecedor  
   - Contrato/Processo  
   - Hostname (FQDN)  
   - Data/Hora (UTC)  
   - Usuário executor  
   - Sistema operacional  
   - Diretório de saída  
   - Chave GPG (se usada)  
   - Diretórios analisados  
   - Padrão de arquivo  
   - Critério de busca  
   - Caminho do arquivo  
   - SHA-256 do arquivo  

4. **Informações de disco rígido (em bytes)**  
   Arquivo:  
   `disk_info_SUPPLIER_HOSTNAME_TIMESTAMP.txt`  

   Contendo:

   ```bash
   lsblk -b -o NAME,SIZE,TYPE,ROTA
   lsblk -b -O
   ```

   (quando suportado pela versão do `lsblk`).

5. **Manifesto de integridade (SHA-256)**  
   Arquivo:  
   `manifest_sha256_SUPPLIER_HOSTNAME_TIMESTAMP.txt`  

   Inclui SHA-256 de:

   - `evidencia_arquivos_...txt`  
   - `arquivos_hashes_...txt`  
   - `cadeia_custodia_...csv`  
   - `disk_info_...txt`

6. **Bundle compactado de evidências**  
   Arquivo:  
   `CASE_ID_SUPPLIER_HOSTNAME_TIMESTAMP.tar.gz`  

   Contém todo o diretório de evidências.

7. **Assinaturas GPG (opcional)**

   Se `SIGN_KEY` válido for informado:

   - `manifest_sha256_...txt.asc`  
   - `CASE_ID_SUPPLIER_HOSTNAME_TIMESTAMP.tar.gz.asc`

---

## 7. Exemplo de Uso (caso log4j)

### Cenário

- `CASE_ID`: `TAREFA-LOG4J-1234`  
- `ANALYST`: `Nome Completo`  
- `ENTITY`: `Entidade`  
- `UNIT`: `Unidade Responsável`  
- `SUPPLIER`: `Fornecedor A`  
- `CONTRACT`: `Contrato 123/2025`  
- `TARGET_DIRS`: `/`  
- `FILE_PATTERN`: `*log4j*.jar`  
- `SIGN_KEY`: `SIGN_KEY_NAO_INFORMADO` (sem assinatura)

### Comando

```bash
sudo /usr/local/sbin/coleta_evidencias_forenses.sh   "TAREFA-LOG4J-1234"   "Nome Completo"   "Entidade"   "Unidade"   "Fornecedor"   "Contrato 123/2025"   "/"   "*log4j*.jar"   "SIGN_KEY_NAO_INFORMADO"
```

### Saída (exemplo de estrutura)

```text
/var/forensics/
└── TAREFA-LOG4J-1234_FornecedorA_servidor01.dominio.com.br_20251211T140501Z/
    ├── evidencia_arquivos_FornecedorA_servidor01.dominio.com.br_20251211T140501Z.txt
    ├── arquivos_hashes_FornecedorA_servidor01.dominio.com.br_20251211T140501Z.txt
    ├── cadeia_custodia_FornecedorA_servidor01.dominio.com.br_20251211T140501Z.csv
    ├── disk_info_FornecedorA_servidor01.dominio.com.br_20251211T140501Z.txt
    ├── manifest_sha256_FornecedorA_servidor01.dominio.com.br_20251211T140501Z.txt
    └── TAREFA-LOG4J-1234_FornecedorA_servidor01.dominio.com.br_20251211T140501Z.tar.gz
```

---

## 8. Fluxo Operacional Resumido

1. **Confirmar parâmetros** com o responsável (CASE_ID, ENTITY, UNIT, SUPPLIER, CONTRACT, diretórios e padrão).
2. Garantir **permissões** (`root`/`sudo`).
3. **Executar** o script com os 9 parâmetros.
4. Registrar no sistema de incidentes:
   - caminho do diretório em `/var/forensics`,
   - SHA-256 do bundle `.tar.gz`,
   - se houver, fingerprint e uso de chave GPG.
5. Transferir o bundle para **mídia adequada**, preferencialmente somente leitura.
6. Arquivar o **CSV de cadeia de custódia** junto ao processo do incidente.

---

## 9. Boas Práticas de Cadeia de Custódia

- Registrar em ata / ferramenta de incidentes:
  - Data/hora da coleta (UTC e horário local).
  - Nome do analista executor.
  - Hostname do servidor.
  - Caminho do diretório de evidências.
  - SHA-256 do bundle e, se houver, fingerprint da chave GPG.
- Não editar manualmente:
  - relatório,
  - CSV,
  - manifesto,
  - disk_info.
- Manter cópias em mídia não regravável, sempre que possível.

---

## 10. Troubleshooting

**Erro: comando obrigatório não encontrado**

- Verificar instalação de:
  - `coreutils`, `util-linux`, `findutils`, `gnupg` (se usar GPG), etc.

**Nenhum arquivo encontrado**

- Revisar:
  - `FILE_PATTERN` (ex.: `*log4j*.jar`),
  - diretórios em `TARGET_DIRS`.

**Falhas de leitura de arquivos**

- Conferir permissões.
- Checar se o script foi executado com privilégios adequados.

**Assinatura GPG não gerada**

- Verificar se:
  - `gpg` está instalado;
  - a chave existe no keyring do usuário executor;
  - o `SIGN_KEY` informado está correto (e-mail/ID da chave).

---

## 11. Referência Rápida

```bash
sudo /usr/local/sbin/coleta_evidencias_forenses.sh   "CASE_ID"   "NOME DO ANALISTA"   "NOME DA ENTIDADE"   "UNIDADE"   "FORNECEDOR"   "NÚMERO DO CONTRATO/PROCESSO"   "DIRETÓRIOS ALVO"   "PADRÃO_DE_ARQUIVO"   "ID_OU_EMAIL_CHAVE_GPG_OU_SIGN_KEY_NAO_INFORMADO"
```

Exemplo genérico:

```bash
sudo /usr/local/sbin/coleta_evidencias_forenses.sh   "INCIDENTE-XYZ-0001"   "Ana Silva"   "Entidade Exemplo"   "Unidade Exemplo"   "FornecedorABC"   "Contrato 999/2025"   "/ /opt /var"   "*log4j*.jar"   "ana.silva@dominio.com.br"
```
