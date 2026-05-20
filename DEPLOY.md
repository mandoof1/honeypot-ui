# HoneySentinel AI — Cloud Deployment Guide

## Option 3: Free Cloud Hosting (Vercel + Render + Neon)

### Architecture
```
Frontend → Vercel (free, custom domain, CDN)
Backend  → Render (free tier, 512MB RAM, sleeps after 15min idle)
Database → Neon (free PostgreSQL, serverless, auto-scales)
AI/ML    → Runs on Render (lazy-loaded to save memory)
```

---

## Step 1: Database (Neon — Free PostgreSQL)

1. Go to [https://neon.tech](https://neon.tech) → Sign up with GitHub
2. Create a new project named `honeysentinel`
3. Copy the connection string (looks like `postgresql://user:pass@ep-xxx.us-east-2.aws.neon.tech/db`)
4. You'll paste this into Render later

---

## Step 2: Backend (Render — Free Web Service)

1. Push your code to GitHub:
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/YOUR_USERNAME/honeypot-ui.git
   git push -u origin main
   ```

2. Go to [https://render.com](https://render.com) → Sign up with GitHub

3. Click **New +** → **Blueprint**

4. Connect your GitHub repo → Select `honeypot-ui`

5. Render reads `render.yaml` and auto-configures:
   - Web service: `honeysentinel-api`
   - Database: `honeysentinel-db` (or use your Neon URL)

6. If using Neon instead of Render DB:
   - In Render dashboard → Environment Variables
   - Set `DATABASE_URL` to your Neon connection string
   - Set `DATABASE_URL_SYNC` to same URL

7. Click **Apply** → Deploy

8. Wait 3-5 minutes for build. Your API will be at:
   `https://honeysentinel-api.onrender.com`

---

## Step 3: Frontend (Vercel — Free)

1. Go to [https://vercel.com](https://vercel.com) → Sign up with GitHub

2. **New Project** → Import `honeypot-ui` repo

3. Configure:
   - Framework Preset: `Vite`
   - Root Directory: `./` (root of repo)
   - Build Command: `npm run build`
   - Output Directory: `dist`

4. Add Environment Variable:
   - Name: `VITE_API_URL`
   - Value: `https://YOUR_RENDER_API_URL.onrender.com/api/v1`

5. Click **Deploy**

6. Your site will be at:
   `https://honeysentinel-ui.vercel.app`

---

## Step 4: Seed the Database

After backend deploys, run this once to seed data:

```bash
curl -X POST https://YOUR_RENDER_API_URL.onrender.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@honeysentinel.io","password":"admin123","name":"Admin","role":"admin"}'
```

Or use the seed script via Render shell:
1. Render Dashboard → Your service → Shell
2. Run: `python -c "from app.seed import seed_database; import asyncio; asyncio.run(seed_database())"`

---

## Step 5: Custom Domain (Optional, Free)

### Vercel:
1. Vercel Dashboard → Your project → Settings → Domains
2. Add your domain → Follow DNS instructions

### Render:
1. Render Dashboard → Your service → Settings → Custom Domain
2. Add domain → Add CNAME record at your registrar

---

## Free Tier Limits

| Service | Limit | Notes |
|---------|-------|-------|
| Vercel | 100GB bandwidth/mo | Generous for dashboard |
| Render | 512MB RAM, 0.1 CPU | Sleeps after 15min idle |
| Neon | 0.5GB storage, 10M queries/mo | Enough for 10k+ sessions |

**Render sleep workaround:** Use a free uptime monitor like [UptimeRobot](https://uptimerobot.com) to ping your API every 14 minutes to keep it awake.

---

## Quick Deploy (One-Click)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/YOUR_USERNAME/honeypot-ui)

Replace `YOUR_USERNAME` with your GitHub username.
