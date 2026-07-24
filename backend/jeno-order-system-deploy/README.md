# JÉNO Order System

## Local development

```sh
npm start
```

Open:

- Storefront: `http://localhost:3000/`
- Admin: `http://localhost:3000/admin.html`
- Health check: `http://localhost:3000/health`

## Render deployment

The included `render.yaml` defines a Node.js web service. Connect this
directory's Git repository to Render and deploy it as a Blueprint.

## Data warning

Products and orders are currently stored in JSON files. On hosts with an
ephemeral filesystem, changes can be lost after a restart or redeployment.
Use a database before relying on this system for real orders.
