# PQC Hybrid Encryption Demo

This repository contains a minimal demonstration of a **hybrid
post‑quantum encryption scheme** implemented in Python.  It combines a
post‑quantum Key Encapsulation Mechanism (Kyber/ML‑KEM via the
OpenSSL OQS provider) with classical X25519 Diffie–Hellman and
authenticated symmetric encryption (AES‑256‑GCM).

## Features

* **FastAPI server** exposing two endpoints:
  * `GET /` – returns a simple HTML page that lets you type a
    message, choose a KEM algorithm and encrypt/decrypt.
  * `POST /encrypt` – accepts a JSON object with a `data` field
    containing a message and an optional `kem` field to override the
    default algorithm.  Returns a JSON package containing the
    ciphertext, nonce, encapsulated key and public keys.
  * `POST /decrypt` – accepts a JSON package returned from
    `POST /encrypt` and recovers the original plaintext.

* **OpenSSL + OQS Provider** compiled inside the Docker image.  The
  build process includes:
  * OpenSSL 3.3.1 built from source with RPATH set.
  * liboqs built as a shared library (no OpenSSL wrapper).
  * oqs‑provider built and installed so that OpenSSL can perform
    Kyber encapsulation/decapsulation.
  * Fallback support for direct liboqs access via ctypes when OpenSSL
    genpkey fails for KEM algorithms.

* **Persistent server keys.**  The Docker Compose configuration
  mounts the `/app/app/keys` directory to `./data/keys` on the host.  This
  ensures that server PQC and X25519 keys are reused across container
  restarts so that decryption is possible.

## Pré-requisitos

Antes de executar o projeto, certifique-se de ter instalado:

* **Docker** (versão 20.10 ou superior)
* **Docker Compose** (versão 2.0 ou superior)
* **Git** (para clonar o repositório)

Para verificar se você tem os pré-requisitos instalados:

```bash
docker --version
docker compose version
git --version
```

## Como Executar o Projeto

### 1. Clonar o Repositório

```bash
git clone <url-do-repositorio>
cd pqc_hybrid_project
```

### 2. Construir e Executar o Container

O projeto usa Docker Compose para facilitar o build e execução. O processo de build pode levar vários minutos, pois compila OpenSSL, liboqs e oqs-provider do código-fonte.

```bash
# Construir a imagem e iniciar o container em modo detached
docker compose up -d --build
```

**Nota:** Na primeira execução, o build pode levar 10-15 minutos dependendo do hardware. Execuções subsequentes serão mais rápidas devido ao cache do Docker.

### 3. Verificar se o Container Está Rodando

```bash
# Verificar o status do container
docker compose ps

# Ver os logs do container
docker compose logs -f pqc-hybrid
```

Você deve ver uma mensagem indicando que o servidor está rodando na porta 3030:
```
INFO:     Uvicorn running on http://0.0.0.0:3030
```

### 4. Acessar a Interface Web

Abra seu navegador e acesse:

```
http://localhost:3030
```

Você verá uma interface web simples onde pode:
- Digitar uma mensagem
- Escolher o algoritmo KEM (Kyber512, Kyber768 ou Kyber1024)
- Criptografar e descriptografar mensagens

### 5. Testar via API (cURL)

#### Criptografar uma mensagem:

```bash
curl -X POST http://localhost:3030/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "data": "Minha mensagem secreta",
    "kem": "Kyber768"
  }'
```

A resposta será um JSON contendo:
- `ciphertext`: texto criptografado (base64)
- `nonce`: nonce usado (base64)
- `kem_ciphertext`: ciphertext do KEM (base64)
- `client_dh_pub_pem`: chave pública X25519 do cliente (base64)
- `public_keys`: chaves públicas do servidor
- `meta`: metadados da política de criptografia

#### Descriptografar uma mensagem:

Salve a resposta completa do comando anterior em um arquivo `response.json` e então:

```bash
curl -X POST http://localhost:3030/decrypt \
  -H "Content-Type: application/json" \
  -d @response.json
```

### 6. Parar o Container

```bash
# Parar o container (mantém os dados)
docker compose stop

# Parar e remover o container (mantém os dados)
docker compose down

# Parar, remover container e volumes (remove TODOS os dados incluindo chaves)
docker compose down -v
```

**Atenção:** Usar `docker compose down -v` irá remover todas as chaves persistentes. Você precisará gerar novas chaves na próxima execução.

## Estrutura do Projeto

```
pqc_hybrid_project/
├── Dockerfile              # Define a imagem Docker com OpenSSL, liboqs e oqs-provider
├── docker-compose.yml      # Configuração do Docker Compose
├── README.md               # Este arquivo
├── app/
│   ├── main.py             # Aplicação FastAPI principal
│   ├── requirements.txt    # Dependências Python
│   ├── crypto/
│   │   ├── encryptor.py   # Lógica de criptografia híbrida
│   │   └── openssl_utils.py # Utilitários para chamadas OpenSSL
│   ├── policy/
│   │   └── policy_pqc.json # Política padrão de criptografia
│   └── static/
│       └── index.html      # Interface web
└── data/
    └── keys/               # Chaves persistentes do servidor (criado automaticamente)
```

## Personalizando o Algoritmo KEM

O algoritmo KEM padrão é **Kyber768**, mas você pode alterá-lo de duas formas:

### 1. Por Requisição (via API)

Passe o campo `kem` no JSON enviado para `/encrypt`:

```bash
curl -X POST http://localhost:3030/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "data": "Mensagem de teste",
    "kem": "Kyber512"  # ou "Kyber768" ou "Kyber1024"
  }'
```

### 2. Alterando a Política Padrão

Edite o arquivo `app/policy/policy_pqc.json`:

```json
{
  "kem": "Kyber1024",
  "symmetric": "AES-256-GCM"
}
```

**Algoritmos Suportados:**
- `Kyber512` (ML-KEM-512) - Menor segurança, chaves menores
- `Kyber768` (ML-KEM-768) - **Padrão** - Balanceado
- `Kyber1024` (ML-KEM-1024) - Maior segurança, chaves maiores

A aplicação mapeia automaticamente os nomes Kyber para seus equivalentes ML‑KEM para suportar diferentes versões do OpenSSL/OQS provider.

## Detalhes de Implementação

### Arquitetura Híbrida

O esquema de criptografia híbrida combina três componentes:

1. **PQC KEM (Kyber/ML-KEM)**: Gera um segredo compartilhado usando criptografia pós-quântica
2. **ECDH (X25519)**: Gera um segundo segredo compartilhado usando criptografia clássica
3. **AES-256-GCM**: Criptografa os dados usando uma chave derivada de ambos os segredos

### Componentes Técnicos

* **HKDF:** Implementação simples do RFC 5869 usando HMAC‑SHA256 para combinar os segredos compartilhados PQC e ECDH em uma chave simétrica de 256 bits. A string de contexto é `pqc-hybrid-demo`.

* **AES‑GCM:** Criptografia simétrica realizada usando a biblioteca `cryptography`. A tag de autenticação de 16 bytes é automaticamente anexada ao ciphertext.

* **OpenSSL CLI:** Todas as operações PQC e ECDH são delegadas ao OpenSSL via subprocess. Esta abordagem torna a implementação independente de bindings Python e demonstra claramente como chamar os primitivos KEM e KDF do OpenSSL a partir de uma linguagem de alto nível.

* **Fallback liboqs:** Quando o OpenSSL `genpkey` falha para algoritmos KEM (comum em algumas versões), o código usa liboqs diretamente via ctypes para gerar chaves e realizar encapsulação/desencapsulação.

### Fluxo de Criptografia

1. Cliente gera um par de chaves X25519 efêmero
2. Servidor encapsula usando a chave pública PQC (Kyber)
3. Cliente e servidor derivam segredo ECDH usando X25519
4. Ambos os segredos são combinados via HKDF para gerar a chave AES
5. Mensagem é criptografada com AES-256-GCM usando a chave derivada

## Solução de Problemas

### Problemas Comuns

#### 1. Container não inicia

**Sintoma:** Container para imediatamente após iniciar

**Solução:**
```bash
# Verificar os logs
docker compose logs pqc-hybrid

# Reconstruir sem cache
docker compose build --no-cache
docker compose up -d
```

#### 2. Erro de provider não encontrado

**Sintoma:** Mensagens como "unable to load provider oqsprovider"

**Solução:**
- Verifique se as variáveis de ambiente estão configuradas corretamente em `docker-compose.yml`
- Certifique-se de que o build completou com sucesso
- Verifique se o arquivo existe: `docker exec pqc-hybrid ls -la /usr/local/lib64/ossl-modules/`

#### 3. Erro ao descriptografar

**Sintoma:** Falha na autenticação ou descriptografia

**Solução:**
- Certifique-se de usar exatamente o JSON retornado por `/encrypt`
- Não modifique nenhum campo do pacote de criptografia
- Verifique se as chaves do servidor foram mantidas (não use `docker compose down -v`)

#### 4. Build muito lento

**Sintoma:** Build demora muito tempo

**Solução:**
- Isso é normal na primeira execução (10-15 minutos)
- Builds subsequentes serão mais rápidos devido ao cache
- Considere aumentar os recursos do Docker (CPU/memória) nas configurações

#### 5. Porta 3030 já em uso

**Sintoma:** Erro ao iniciar o container sobre porta já em uso

**Solução:**
```bash
# Verificar o que está usando a porta
netstat -ano | findstr :3030  # Windows
lsof -i :3030                 # Linux/Mac

# Ou alterar a porta no docker-compose.yml
# Altere "3030:3030" para "3031:3030" (ou outra porta)
```

### Verificações Úteis

```bash
# Verificar se o container está rodando
docker compose ps

# Entrar no container para debug
docker exec -it pqc-hybrid bash

# Verificar versão do OpenSSL
docker exec pqc-hybrid openssl version

# Listar providers disponíveis
docker exec pqc-hybrid openssl list -providers

# Verificar chaves geradas
docker exec pqc-hybrid ls -la /app/app/keys/
```

## Desenvolvimento

### Executar em Modo de Desenvolvimento

Para desenvolvimento local sem Docker:

```bash
# Instalar dependências Python
pip install -r app/requirements.txt

# Configurar variáveis de ambiente
export OPENSSL_MODULES=/usr/local/lib64/ossl-modules
export OSSL_PROVIDER_PATH=/usr/local/lib64/ossl-modules
export LD_LIBRARY_PATH=/usr/local/lib64:/usr/local/lib
export PATH=/usr/local/bin:$PATH

# Executar o servidor
cd app
uvicorn main:app --host 0.0.0.0 --port 3030 --reload
```

**Nota:** Isso requer que OpenSSL, liboqs e oqs-provider estejam instalados localmente.

### Testes

Para testar a API programaticamente:

```python
import requests
import json

# Criptografar
response = requests.post('http://localhost:3030/encrypt', json={
    'data': 'Mensagem de teste',
    'kem': 'Kyber768'
})
encrypted_package = response.json()

# Descriptografar
response = requests.post('http://localhost:3030/decrypt', json={
    'package': encrypted_package
})
decrypted = response.json()
print(decrypted['plaintext'])  # Deve imprimir "Mensagem de teste"
```

## Agradecimentos

Este projeto utiliza documentação e ferramentas do projeto
[Open Quantum Safe](https://openquantumsafe.org/), incluindo
liboqs e o oqs provider para OpenSSL. Também utiliza a biblioteca
[cryptography](https://cryptography.io/) para criptografia simétrica
e [FastAPI](https://fastapi.tiangolo.com/) para a interface web.

## Licença

Este projeto é fornecido como demonstração educacional. Consulte os
arquivos de licença dos projetos dependentes para mais informações.