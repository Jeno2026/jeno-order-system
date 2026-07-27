# Move Products and Orders to PostgreSQL

This release stores members, products, and orders in the PostgreSQL database
configured by `DATABASE_URL`.

## Before deploying

1. Open the existing admin page.
2. Export or record the current orders as a backup.
3. Confirm Render still has the `DATABASE_URL` environment variable.
4. Confirm `data/products.json` and `data/orders.json` in GitHub contain the
   legacy records that should be imported.

## Automatic first-start import

On startup, the server creates `products` and `orders` tables.

- When the `products` table is empty, it imports `data/products.json`.
- When the `orders` table is empty, it imports `data/orders.json`.
- It never overwrites a non-empty PostgreSQL table.
- Later product and order changes are written only to PostgreSQL.

## Render deployment

Deploy the latest commit and inspect the deployment logs for:

```text
Migrated N products from JSON to PostgreSQL.
Migrated N orders from JSON to PostgreSQL.
Server running at ...
```

After deployment:

1. Open the customer menu and confirm all products appear.
2. Open Admin > Orders and confirm the orders appear.
3. Add a temporary product, refresh the page, and then delete it.
4. Create one test order and verify it appears in both Admin and the member
   account order history.

Keep the JSON files in GitHub as a legacy backup. They are no longer changed by
the running website.
