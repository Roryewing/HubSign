# Deploying HubSign (free)

Host: Oracle Cloud always-free VM. Database + files: Supabase Pro (separate project recommended for signed contracts).

1. **Supabase**: new project. Storage > create a *private* bucket `hubsign`, then Storage > S3 connection > create access keys.
   Connect > copy the **session pooler** string (port 5432).
2. **Oracle**: create an Always Free Ampere A1 VM (Ubuntu), open ports 80/443 in the VCN security list and `sudo ufw allow 80,443`.
   Install Docker (`curl -fsSL https://get.docker.com | sh`). Point a DNS A record for your host at the VM.
3. On the VM: `git clone https://github.com/Roryewing/HubSign.git && cd HubSign/deploy/oracle`, `cp .env.example .env`, fill it in, `docker compose up -d --build` (the first build takes several minutes). Migrations run on boot; open `https://HOST` and create the admin account.

Check on first run: the `docuseal/docuseal` image must have an arm64 build (Ampere), and uploads must land in the Supabase bucket.
Fallback host: `deploy/render/` (Render free + keepalive ping; may be too little RAM).
