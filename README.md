
# 🔐 Secure Messenger – Sistema Modular de Comunicação Segura

## 🎯 Objetivo do Projeto
O **Secure Messenger** é um sistema desenvolvido em **Python com FastAPI**, projetado para demonstrar na prática os princípios fundamentais da **criptografia moderna** aplicados à comunicação segura.  
Ele garante os quatro pilares da segurança da informação:

- **Confidencialidade** → apenas o destinatário pode ler a mensagem.  
- **Autenticidade** → o remetente é realmente quem diz ser.  
- **Integridade** → o conteúdo não é alterado durante o envio.  
- **Não-repúdio** → o remetente não pode negar que enviou a mensagem.

O sistema combina **criptografia simétrica (AES)**, **assimétrica (RSA)**, **assinaturas digitais**, **funções hash seguras (SHA-256)** e uma **mini Autoridade Certificadora (CA)**, tudo integrado a uma **interface web intuitiva** e **banco de dados SQLite**, empacotado em **Docker** para fácil execução.

<img width="1907" height="963" alt="2025-10-28_13-15" src="https://github.com/user-attachments/assets/9de8aee9-5424-4b90-9ab1-3d0af5c6059b" />

Este projeto foi desenvolvido exclusivamente para fins acadêmicos, como parte de uma atividade prática da disciplina de Criptografia e Segurança da Informação.
Seu objetivo é demonstrar, de forma didática, a aplicação de conceitos de criptografia híbrida (RSA + AES), assinaturas digitais, funções hash e certificados digitais (X.509) em um sistema funcional de comunicação segura.
Não deve ser utilizado em ambientes de produção ou para fins comerciais sem adaptações e revisões de segurança adicionais.

---

## 🧱 Arquitetura do Sistema

### Camadas Principais

| Camada | Tecnologias e Funções |
|--------|-----------------------|
| **Frontend (UI)** | HTML, CSS, JavaScript – Interface web interativa para criar usuários, enviar e ler mensagens. |
| **Backend (API)** | Python + FastAPI – Gerencia criptografia, geração de chaves, certificados, envio e leitura de mensagens. |
| **Banco de Dados (SQLite)** | Armazena chaves, certificados, mensagens cifradas, envelopes e logs de auditoria. |
| **Ambiente (Docker)** | Isolamento e portabilidade: `docker compose up --build` executa tudo automaticamente. |

---

## 🧩 Fluxo de Operações

### 1️⃣ Inicialização da CA
- O sistema gera uma **chave RSA 3072 bits** e cria um **certificado raiz x.509 autoassinado**.  
- Este certificado representa a **Mini Autoridade Certificadora (CA)**.  
- A chave privada da CA é usada para **assinar digitalmente** certificados de usuários e logs.  
- Armazenados na tabela `ca`:
  - `ca_privkey_pem` → chave privada RSA.  
  - `ca_cert_pem` → certificado raiz x.509 (com a chave pública).  

### 2️⃣ Criação de Usuários
- Ao criar um usuário (ex.: “Alice”), o sistema gera um **par de chaves RSA (privada e pública)**.  
- A CA assina a chave pública do usuário, emitindo um **certificado digital x.509**.  
- Armazenado na tabela `users`:  
  - `privkey_pem` → chave privada do usuário.  
  - `cert_pem` → certificado assinado pela CA.  

### 3️⃣ Envio de Mensagens (Alice → Bob)
1. Alice escreve a mensagem.  
2. O sistema gera uma **chave AES aleatória (simétrica)** e cifra o corpo com **AES-GCM**.  
3. Calcula o **hash SHA-256** da mensagem e assina-o com a **chave privada RSA de Alice** → criando a **assinatura digital**.  
4. A chave AES é **criptografada com a chave pública RSA de Bob** (híbrido).  
5. Dados armazenados:  
   - `messages` → corpo cifrado, nonce, tag, assinatura, hash.  
   - `envelopes` → chave AES cifrada para cada destinatário.  
   - `audit` → evento “message_send” assinado pela CA.  

### 4️⃣ Leitura de Mensagens (Bob)
1. Bob usa sua **chave privada RSA** para decifrar a **chave AES**.  
2. Com a chave AES, ele decifra o corpo da mensagem (AES-GCM garante integridade).  
3. O sistema verifica o **certificado da Alice** → valida assinatura da CA.  
4. Recalcula o **hash SHA-256** da mensagem e compara com o da assinatura.  
   - Se coincidir → mensagem é autêntica e íntegra.  
5. Evento registrado no log de auditoria (`audit`).  

### 5️⃣ Auditoria e Verificação
- Cada evento (envio, leitura, criação) gera um log com:  
  - `payload_json` → dados do evento.  
  - `sig_hex` → assinatura digital gerada pela CA.  
- Ao clicar em **“Verificar Auditoria”**, o sistema recalcula os hashes e verifica cada assinatura com a **chave pública da CA**.  
  - Resultado: “✅ Audit OK” → logs íntegros e autênticos.

O fluxograma abaixo ilustra o funcionamento completo do Secure Messenger, desde a inicialização da **Autoridade Certificadora (CA)** até a leitura e verificação das mensagens.
Nele é possível visualizar o fluxo de dados entre os componentes principais do Frontend, Backend, Banco de Dados e CA. além das operações criptográficas (RSA, AES-GCM, SHA-256) e das etapas de auditoria assinada digitalmente.
Cada bloco representa uma ação real executada pelo sistema, mostrando de forma clara como a confidencialidade, autenticidade, integridade e não repúdio são garantidos em todas as fases da comunicação.

<img width="1840" height="1500" alt="Diagrama em branco" src="https://github.com/user-attachments/assets/a675afcc-ed3c-4c8f-86db-561701b47772" />

---

## ⚙️ Tecnologias Utilizadas

| Componente | Tecnologia | Função |
|-------------|-------------|--------|
| Linguagem | Python 3.11 | Backend e criptografia |
| Framework Web | FastAPI | API REST moderna e performática |
| Criptografia | Cryptography (RSA, AES, SHA-256, PSS, OAEP) | Operações criptográficas seguras |
| Banco de Dados | SQLite3 | Armazenamento local e leve |
| Interface Web | HTML + CSS + JS | Interação com API |
| Contêiner | Docker | Execução isolada e portável |

---

## 🔐 Conceitos Criptográficos Aplicados

- **RSA (3072 bits)** → Criptografia assimétrica e assinaturas digitais (RSA-PSS).  
- **AES-GCM (256 bits)** → Criptografia simétrica autenticada (AEAD).  
- **SHA-256** → Função hash para garantir integridade.  
- **x.509** → Padrão de certificados digitais.  
- **CA (Autoridade Certificadora)** → Assina e valida chaves públicas.  

---

## 🧠 Decisões Técnicas e Segurança

- **Padding OAEP e PSS** → padrões modernos e seguros para RSA.  
- **Múltiplos destinatários** → uma chave AES cifrada para cada usuário.  
- **Timestamp e Nonce** → evita replay attacks.  
- **Logs assinados digitalmente** → garante rastreabilidade e não repúdio.  

### Limitações
- As chaves privadas ficam armazenadas em texto puro no banco (risco se servidor for comprometido).  
- O sistema não possui Perfect Forward Secrecy (PFS).  

### Melhorias Futuras
1. **Criptografar chaves privadas no banco** (via PBKDF2/Argon2).  
2. **Mover criptografia para o cliente (Zero-Knowledge)** via WebCrypto API.  
3. **Implementar PFS** com ECDH (como o Signal).  
4. **Adicionar revogação de certificados (CRL)**.

---

## 🚀 Como Executar o Projeto

```bash
# 1. Clonar o repositório
git clone https://github.com/pietrohoff/SecureMessenger
cd SecureMessenger

# 2. Construir e iniciar o container
docker compose up --build

# 3. Acessar o sistema
http://localhost:8000
```

---

## 📂 Estrutura de Pastas

```
SecureMessenger/
├── app/
│   ├── main.py              # FastAPI (rotas e endpoints)
│   ├── secure_core.py       # Lógica criptográfica principal
│   ├── templates/
│   │   └── index.html       # Interface web
│   └── database.db          # Banco SQLite
├── Dockerfile
├── docker-compose.yml
└── README.md

SecureMessenger/
├── app/                          # (reservado p/ assets/auxiliares, conforme evolução)
│    ├── core/                    # módulos auxiliares (ex.: utilidades, validações)
│    │   └── secure_core.py       # núcleo criptográfico (RSA, AES-GCM, X.509)
│    ├── data/
│    │   └── secure_messenger.db  # banco SQLite
├── frontend/
│   ├── index.html                # UI principal
│   └── index2.html               # UI alternativa/experimental
├── main.py                       # aplicação FastAPI (rotas/API)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## 🧩 Conclusão
O **Secure Messenger** demonstra, de forma prática e didática, a aplicação de técnicas criptográficas modernas em um sistema real de comunicação.  
Ele mostra **como combinar RSA, AES e SHA-256** para garantir confidencialidade, autenticidade, integridade e não repúdio, além de simular uma **autoridade certificadora local (CA)** e uma **camada de auditoria assinada digitalmente**.  
O projeto é 100% funcional, executável via Docker, e fornece uma base sólida para evoluir em direção a um **modelo de mensageria segura completo, comparável a arquiteturas como Signal Protocol**.
