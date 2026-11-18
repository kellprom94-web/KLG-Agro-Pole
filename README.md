# КЛГ Агро Поле

Облік полів, сівозміни, агрооперацій і техніки для ТОВ «КЛГ Агро».

- `web/index.html` — сторінка програми (карта MapLibre + MapTiler).
- `worker/src.js` — Cloudflare Worker: віддає сторінку і API даних (D1).
- `python3 build.py` — збирає `worker/worker.js` (сторінка вбудовується у воркер).
- Розгортання: Cloudflare Workers Builds з цього репозиторію (`npx wrangler deploy`).
- Секрет `APP_PASSWORD` задається в налаштуваннях воркера в Cloudflare.
