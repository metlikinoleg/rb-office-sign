# rb-office-sign

Интеграция OnlyOffice с КриптоПро DSS для подписания документов.

## Архитектура

```
rb-office-sign/
├── backend/    # Python FastAPI сервис интеграции
├── nginx/      # Конфигурация обратного прокси
└── docker/     # Docker Compose и вспомогательные файлы
```

## Стек

- **OnlyOffice** — редактор документов
- **КриптоПро DSS** — облачная электронная подпись
- **FastAPI** — backend-сервис интеграции
- **Nginx** — обратный прокси
- **Docker Compose** — оркестрация

## Быстрый старт

```bash
docker compose -f docker/docker-compose.yml up -d
```
