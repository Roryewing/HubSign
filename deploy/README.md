# Deploying HubSign (free)

Host: Oracle Cloud always-free VM. Database + files: Supabase Pro (separate project recommended for signed contracts).

1. **Supabase**: new project. Storage > create a *private* bucket `hubsign`, then Storage > S3 connection > create access keys.
   Connect > copy the **session pooler** string (port 5432).
2. **Oracle**: create an Always Free Ampere A1 VM (Ubuntu), open ports 80/443 in the VCN security list and `sudo ufw allow 80,443`.
   Install Docker (`curl -fsSL https://get.docker.com | sh`). Point a DNS A record for your host at the VM.
3. On the VM: `git clone https://github.com/Roryewing/HubSign.git && cd HubSign/deploy/oracle`, `cp .env.example .env`, fill it in, `docker compose up -d --build` (the first build takes several minutes). Migrations run on boot; open `https://HOST` and create the admin account.

Check on first run: the `docuseal/docuseal` image must have an arm64 build (Ampere), and uploads must land in the Supabase bucket.
Fallback host: `deploy/render/` (Render free + keepalive ping; may be too little RAM).

## Keep a free Supabase project awake

Free Supabase projects pause after about a week with no database activity. A daily query from the VM prevents that
(`crontab -e` on the VM; adjust the path):

    0 6 * * * cd ~/HubSign/deploy/oracle && docker compose exec -T app bin/rails runner 'ActiveRecord::Base.connection.execute("select 1")' >/dev/null 2>&1

Free projects also have no automatic backups: take a `pg_dump` now and then, and keep the Supabase bucket's file limits in
mind (check the current free-tier storage and per-file limits on supabase.com/pricing).

## Check storage before the first upload

Placeholders left in `.env` (PROJECTREF in `S3_ENDPOINT`, the default `AWS_REGION`) make Supabase answer every request with an
empty `400 BadRequest`. After `docker compose up -d`, run:

    docker compose exec -T -w /app app /app/bin/bundle exec rails runner 'c=ActiveStorage::Blob.service.client.client; b=ENV["S3_ATTACHMENTS_BUCKET"]; {list: ->{c.list_objects_v2(bucket: b, max_keys: 1)}, put: ->{c.put_object(bucket: b, key: "hs-test.txt", body: "hi")}, head: ->{c.head_object(bucket: b, key: "hs-test.txt")}}.each{|n,f| begin; f.call; puts "#{n} OK"; rescue => e; puts "#{n}: #{e.class}: #{e.message[0,200]}"; end}'

All three lines should say OK. `docker compose up -d --force-recreate app` applies a changed `.env`.
