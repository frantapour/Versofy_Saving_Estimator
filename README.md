# Versofy savings calculator

Sales tool that estimates a customer's monthly, 10-year and 20-year savings on a Versofy solar subscription, with add-ons, a customer PDF proposal and admin-managed prices, packages, add-ons and tariffs.

- `public/index.html`: the calculator (single page).
- `server.js`: serves the page and a small JSON API that stores the admin settings in Postgres.

Every quote reads the latest saved settings. The page checks for changes every minute, and again right before each PDF is made. Each PDF shows the date of the settings it used.

## Deploy on Railway

1. In Railway, choose **New project → Deploy from GitHub repo** and pick this repo. Railway detects Node and runs `npm start`.
2. In the same project, choose **New → Database → PostgreSQL**.
3. Open the calculator service's **Variables** tab and add these variables:
   - `DATABASE_URL` = `${{Postgres.DATABASE_URL}}` (a reference to the database)
   - `ADMIN_PASSWORD`: the password admins use to edit prices and tariffs
   - `SESSION_SECRET`: any long random string, so sign-ins survive redeploys
   - `SALES_PASSWORD` (optional): if set, the whole calculator asks for this team password first
4. Under **Settings → Networking**, choose **Generate domain**, or add your own domain.
5. Set the health check path to `/health` (optional).

To change prices, open the calculator, scroll to the bottom and choose **Admin sign-in**. The admin panel lets you edit package fees, yearly increases and specs, add or hide packages, set add-on fees and edit tariffs. **Save for everyone** applies the changes to all users, and the panel keeps a list of recent changes.

## Run locally

```
npm install
ADMIN_PASSWORD=choose-one npm start
```

Without `DATABASE_URL`, the settings are saved to `data/settings.json`.
