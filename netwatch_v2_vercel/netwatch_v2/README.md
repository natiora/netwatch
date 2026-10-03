# NetWatch V2 — version Vercel

Variables d'environnement (Vercel > Settings > Environment Variables) :
- DATABASE_URL  (fournie par Neon via le Marketplace Vercel ; préférez l'URL "pooled")
- NETWATCH_SECRET  (longue valeur aléatoire)
- NETWATCH_ADMIN_EMAIL / NETWATCH_ADMIN_PASSWORD  (créés au premier démarrage)
- CRON_SECRET  (valeur aléatoire ; Vercel l'envoie automatiquement au cron)

Checks : HTTP et TCP uniquement (le ping n'existe pas sur Vercel).
Les checks sont lancés par /api/cron (vercel.json), au plus une fois par minute.
