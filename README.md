# JWT Pentest Helper

Web-инструмент для **авторизованного** тестирования JWT: декодирование, редактирование payload/header и генерация тестовых токенов под распространённые классы уязвимостей.

## Какие атаки покрываются

- Unverified Signature
- Flawed Signature Verification (`alg=none`)
- Algorithm Confusion (`RS↔HS`)
- Weak Signing Key
- `jwk` Header Injection
- `jku` Header Injection
- `kid` Header Path Traversal

## Установка и запуск

### Вариант 1: локально без контейнера

Откройте `index.html` в современном браузере.

### Вариант 2: Docker Compose

```bash
docker compose up --build
```

После запуска откройте: `http://localhost`

## Базовый сценарий использования

1. Вставьте исходный JWT.
2. Нажмите **Decode token**.
3. Отредактируйте payload/header при необходимости.
4. Выберите нужный пресет атаки.
5. Заполните Attack-specific input (если нужен этим пресетом).
6. Нажмите **Generate** и используйте полученный токен в тесте.

> Важно: инструмент не подставляет значения claims за пользователя; всё берётся из введённого JWT и ваших входных данных.

## Скриншоты



## Disclaimer

Используйте только на системах, для которых у вас есть явное разрешение на тестирование.
