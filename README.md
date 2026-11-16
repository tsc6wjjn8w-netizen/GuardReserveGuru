# GuardReserveGuru v4: accounts + Cloudflare database

Login is **name/callsign + last 4 of phone**. Each person's data lives in your Cloudflare D1 database and follows them to any device. It still works offline and syncs when back online.

Run these from inside this folder. One command per step.

## 1. Log in to Cloudflare (one time)

```
npx wrangler login
```

## 2. Create the database

```
npx wrangler d1 create grg-db
```

Copy the `database_id` it prints into `wrangler.toml` (replace `PASTE-YOUR-DATABASE-ID-HERE`).

## 3. Create the tables

```
npx wrangler d1 execute grg-db --remote --file=schema.sql
```

## 4. Create the site and deploy

```
npx wrangler pages project create guardreserveguru --production-branch main
```

```
npx wrangler pages deploy public --project-name guardreserveguru
```

Your site will be at `https://guardreserveguru.pages.dev`.

## 5. Lock it down (recommended, do before sharing the link)

Pepper: a secret mixed into every PIN hash. Set it once, before the first account exists, and never change it (changing it breaks all logins).

```
npx wrangler pages secret put PIN_PEPPER --project-name guardreserveguru
```

Redeploy once after setting secrets (repeat the deploy command in step 4).

## Updating the site later

Edit `public/index.html`, then re-run the deploy command from step 4. User data is not touched.

## Test locally first (optional)

```
npx wrangler d1 execute grg-db --local --file=schema.sql
```

```
npx wrangler pages dev public
```

## How it behaves

- **Same name twice:** names are unique (case-insensitive). The second person to pick "Smith" must use something else, like "Smith J".
- **Wrong PIN:** 5 wrong tries on an account locks it for 15 minutes.
- **First account on an existing browser:** "Create account" offers to import the data already saved in that browser.
- **Two devices edit at once:** the second device gets a bar asking whether to use the latest or keep its own copy. Nothing is silently overwritten.
- **Sessions:** stay signed in for 90 days on a device. Sign out clears local data on that device.

## Security reality check

Four digits is only 10,000 combinations. The lockout and the pepper make guessing impractical, but anyone who knows someone's name and last 4 can open that account. That's fine for low-stakes personal tracking; it is not strong security. Keep entries generic (no PII or CUI), same as the app already says.
