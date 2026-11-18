# How to Deploy Lavonne Gas on Render (Free)

## Important Warning about Free Tier
Render free web services have an **ephemeral filesystem**.  
This means your SQLite database and uploaded images can be **wiped** when the service restarts or sleeps.

For serious business use later you should move to PostgreSQL.  
For testing and starting, SQLite is okay.

## Step-by-step on Render

1. Go to https://render.com and create a free account (sign up with GitHub is easiest).

2. Create a new **Web Service**.

3. Connect your GitHub repository (you will need to upload this project to GitHub first)
   OR use the "Deploy from existing image / manual" options if available.
   Easiest for beginners: push the project to a GitHub repo.

4. Settings on Render:
   - **Name**: lavonne-gas (or any name)
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
   - **Instance Type**: Free

5. Environment Variables (add these):
   - Key: `LAVONNE_SECRET`
   - Value: (put a long random string, e.g. generated from https://randomkeygen.com)

6. Click **Create Web Service**.

7. Wait for it to build and deploy.  
   You will get a URL like: `https://lavonne-gas.onrender.com`

8. Open that URL → go to `/setup` to create the administrator account.

## Custom Domain (later)
After it is working, you can buy a domain (e.g. lavonnegas.co.ke) and point it to your Render service.

