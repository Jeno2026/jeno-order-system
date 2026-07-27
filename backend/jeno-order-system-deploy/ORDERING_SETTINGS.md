# Ordering Calendar Settings

Open **Admin > Settings** to configure:

- Minimum advance notice in days
- Maximum accepted orders per fulfillment date
- Weekly closed weekdays
- Special closed dates
- Available pickup or delivery times

Settings are stored in PostgreSQL and are applied to the customer checkout.
The server validates the selected date and time again when an order is placed.
Cancelled orders do not count toward the daily limit.

Default settings on first deployment:

- 2 days advance notice
- Sunday closed
- 10 orders per date
- 10:00, 12:00, 14:00, and 16:00 time slots
