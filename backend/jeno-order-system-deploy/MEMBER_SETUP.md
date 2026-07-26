# JÉNO member setup

The member system uses PostgreSQL for persistent customer data. Email
verification is currently disabled, so no email provider or custom domain is
required.

## 1. Create PostgreSQL on Render

1. In Render, choose **New → Postgres**.
2. Create the database in the same region as the JÉNO web service.
3. Open the database and copy its **Internal Database URL**.
4. Open the JÉNO web service → **Environment**.
5. Add:
   - Key: `DATABASE_URL`
   - Value: the Internal Database URL

The required member tables are created automatically during the next deploy.

Do not put the database URL or customer passwords in GitHub.

## 2. Deploy and test

1. Deploy the latest GitHub commit.
2. Open the storefront and select **Sign in → Create account**.
3. Register an account. Registration signs the customer in immediately.
4. Place an order, then open the member account to confirm the order
   appears under **Your orders**.
5. Sign in to the administrator page and open the **Members** tab.
6. To help a customer who forgot their password, select **Reset password**,
   enter a temporary password with at least eight characters, and give it to
   the customer privately. All existing member sessions are signed out.

Customers can still check out as guests. Member passwords are stored only as
one-way scrypt hashes and are never displayed in the administrator page.
