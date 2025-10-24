# Secure Messenger — FastAPI + Web UI + Docker

Sistema de **mensagens seguras** com criptografia híbrida (AES-256-GCM + RSA-OAEP),
assinatura RSA-PSS, hash SHA-256, **mini-AC**, **anti-replay** (timestamp+nonce),
**log assinado** e **UI Web** simples. Empacotado em **Docker**.

## Rodar com Docker
```bash
docker compose up --build
# Backend: http://localhost:8000
# Web UI:  http://localhost:8000/
```

O banco SQLite fica em `./app/data/secure_messenger.db` (mapeado via volume).

## Primeiros passos (via UI)
1) Abra `http://localhost:8000`, clique **Inicializar CA**.
2) Crie usuários (ex.: Alice, Bob, Carol).
3) Envie mensagem de **Alice** para **Bob**/**Carol**.
4) Abra a aba Inbox do Bob e leia as mensagens.

## API (principais endpoints)
- `POST /init-ca`
- `POST /users` body: `{ "name": "Alice" }`
- `GET /users`
- `POST /send` body: `{ "sender": "Alice", "to": ["Bob"], "subject":"Oi", "body":"..." }`
- `GET /inbox/{user}`
- `GET /read/{user}/{msg_id}`
- `GET /audit`
- `GET /audit/verify`
```

## Funcionamento
A aplicação Secure Messenger é um sistema web completo de troca de mensagens seguras, construído para demonstrar de forma prática como funcionam os principais pilares da segurança da informação: confidencialidade, autenticidade, integridade e não repúdio. Ela usa uma combinação de criptografia simétrica (AES) e assimétrica (RSA), além de assinaturas digitais e funções hash (SHA-256) para garantir que cada mensagem enviada seja privada, autêntica e impossível de ser alterada sem detecção. Tudo isso é gerenciado por uma mini “Autoridade Certificadora” (CA) local, que simula um cartório digital responsável por gerar e validar chaves públicas e certificados.

O fluxo começa com a inicialização da CA, que cria as chaves-raiz e prepara o sistema para aceitar usuários. Quando um novo usuário (como Alice, Bob ou Carol) é criado, o sistema gera automaticamente um par de chaves RSA — uma privada (guardada pelo sistema) e uma pública (assinada pela CA). Essa chave pública será usada pelos outros usuários para enviar mensagens cifradas de forma que apenas o destinatário possa ler. Assim, o ato de criar um usuário é, na prática, como gerar uma identidade digital autenticada.

Na hora de enviar uma mensagem, a aplicação faz uma criptografia híbrida: primeiro ela cria uma chave AES aleatória e usa essa chave para cifrar o conteúdo da mensagem (porque o AES é rápido e eficiente). Depois, essa chave AES é cifrada com a chave pública RSA do destinatário, garantindo que só ele — com sua chave privada — consiga decifrar o texto. Antes do envio, o remetente ainda assina digitalmente o hash da mensagem com sua chave privada, garantindo que o destinatário possa confirmar quem enviou e que o conteúdo não foi alterado. Quando o destinatário abre a mensagem, o sistema decifra a chave AES com sua chave privada RSA, abre a mensagem, verifica a assinatura e confirma a integridade do texto.

Por fim, todas as operações — criação de usuários, envios, leituras e verificações — são registradas em um log de auditoria assinado digitalmente pela CA. Isso garante rastreabilidade e impede adulteração posterior. A aplicação foi desenvolvida com Python + FastAPI no backend (para as rotas e lógica criptográfica) e HTML, CSS e JavaScript no frontend, com um visual moderno e explicativo. Ela roda totalmente em containers Docker, o que facilita a execução em qualquer sistema operacional. O resultado é uma ferramenta educativa, segura e visualmente acessível, que mostra passo a passo como a criptografia moderna protege a troca de informações no mundo real.