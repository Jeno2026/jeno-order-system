# JÉNO member setup

The member system uses PostgreSQL for persistent customer data and Resend for
verification and password-reset emails.

## 1. Create PostgreSQL on Render

1. In Render, choose **New → Postgres**.
2. Create the database in the same region as the JÉNO web service.
3. Open the database and copy its **Internal Database URL**.
4. Open the JÉNO web service → **Environment**.
5. Add:
   - Key: `DATABASE_URL`
   - Value: the Internal Database URL

The required member tables are created automatically during the next deploy.

## 2. Configure email delivery

1. Create a Resend account at https://resend.com/.
2. Verify the domain used for customer email.
3. Create an API key.
4. Add these Render environment variables:

   - `RESEND_API_KEY` = the Resend API key
   - `EMAIL_FROM` = `JÉNO Pâtisserie <orders@your-domain.com>`
   - `APP_BASE_URL` = `https://jeno-order-system.onrender.com`

Do not put the API key, database URL, or customer passwords in GitHub.

## 3. Deploy and test

1. Deploy the latest GitHub commit.
2. Open the storefront and select **Sign in → Create account**.
3. Register with an email address you can access.
4. Open the verification email and select the verification link.
5. Sign in, place an order, then open the member account to confirm the order
   appears under **Your orders**.
6. Test **Forgot password** and its emailed reset link.
7. Sign in to the administrator page and open the **Members** tab.

Customers can still check out as guests. Member passwords are stored only as
one-way scrypt hashes and are never displayed in the administrator page.
