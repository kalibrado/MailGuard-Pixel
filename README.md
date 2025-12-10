# MailGuard Pixel

Surveillance discrète des accès email via pixel 1x1

## Introduction

MailGuard Pixel est un micro-service conçu pour détecter le chargement d’un pixel invisible (1x1) intégré dans des emails internes. L’objectif est de signaler toute consultation provenant d’une adresse IP externe ou non autorisée, ce qui peut indiquer une fuite d’information, un transfert d’email non prévu ou un accès depuis un environnement non maîtrisé.

Le système repose sur un serveur Flask minimaliste capable de loguer chaque requête en temps réel, avec possibilité d’envoyer des alertes automatiques.

---

## Fonctionnalités

* Serveur HTTP minimal basé sur Flask
* Pixel 1x1 statique (PNG)
* Logging en temps réel de chaque accès
* Détection des IP internes vs externes
* Support du header `X-Forwarded-For`
* Compatible avec un déploiement Docker
* Option d’alerte intégrable (Webhook, Slack, Teams, email…)
* Aucun cron ou service supplémentaire requis

---

## Architecture

```
Mail client → Pixel (email) → Flask Server → Analyse IP → Logs / Alertes
```

Gmail Web charge les images via un proxy, ce qui garantit que tout chargement direct depuis une IP inconnue est hautement suspect.

---

## Installation

### 1. Cloner le projet

```bash
git clone https://example.com/mailguard-pixel.git
cd mailguard-pixel
```

### 2. Installer les dépendances

```bash
pip install flask
```

### 3. Lancer le service

```bash
python app.py
```

Le service écoute par défaut sur le port **8080**.

---

## Fichiers importants

### `app.py`

Contient le serveur Flask, la logique de détection d’IP et le logging en temps réel.

### `pixel.png`

Pixel 1x1 blanc utilisé comme image de tracking interne.

---

## Exemple de log

```
[2025-12-10T21:54:00.245891] IP=66.249.89.21 TYPE=EXTERNE UA="Mozilla/5.0 (gae-proxy)"
```

Sorties typiques :

* IP interne = OK
* IP Gmail proxy = normal
* IP externe inconnue = anomalie potentielle

---

## Déploiement en Docker

### Dockerfile

```Dockerfile
FROM python:3.12-alpine
WORKDIR /app
COPY app.py pixel.png ./
RUN pip install flask
EXPOSE 8080
CMD ["python", "app.py"]
```

### Build & run

```bash
docker build -t mailguard-pixel .
docker run -p 8080:8080 mailguard-pixel
```

---

## Intégration dans un email

Inclure l’image via un lien direct :

```html
<img src="https://ton-domaine/pixel.png" width="1" height="1" style="display:none" />
```

---

## Sécurité

* Ne jamais exposer le service sans reverse proxy HTTPS
* Limiter les accès au strict nécessaire
* Mettre en place un système d’alertes si IP externe détectée
* Journaliser dans un emplacement sécurisé

---

## Limitations

* Gmail Web utilise un proxy d’images: l’IP de l’utilisateur final n’est jamais exposée
* Certains clients bloquent le chargement automatique d’images
* Le pixel doit être hébergé sur un domaine accessible publiquement