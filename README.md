# NetWatch V2 — version Vercel

Variables d'environnement (Vercel > Settings > Environment Variables) :
- DATABASE_URL (Neon, URL "pooled")
- NETWATCH_SECRET (longue valeur aléatoire)
- NETWATCH_ADMIN_EMAIL (minuscules) / NETWATCH_ADMIN_PASSWORD
- CRON_SECRET (valeur aléatoire)

Checks : HTTP et TCP uniquement (pas de ping sur Vercel).
Déclenchement : cron-job.org appelle chaque minute GET /api/cron avec l'en-tête
Authorization: Bearer <CRON_SECRET>. Le dashboard déclenche aussi les checks (/api/run) tant qu'il est ouvert.
Dates affichées en heure de Paris et en UTC+3.

Déploiement : vercel --prod
