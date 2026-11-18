# Deploying SafeVote

Replace `example.com` with your domain and `203.0.113.10` with your server's public IP everywhere below.

## 1. Cloud server (2 marks)
Create an Ubuntu 24.04 VM (AWS Lightsail, DigitalOcean, Azure or similar). The smallest size is enough.
Open ports 22, 80 and 443 in the provider firewall. Then on the server:

    sudo apt update && sudo apt install -y python3-venv nginx git curl ufw
    sudo ufw allow OpenSSH && sudo ufw allow 'Nginx Full' && sudo ufw --force enable

## 2. DNS (8 marks) and subdomains (3 marks)
At your domain registrar or DNS host, create these records:

| Type | Name    | Value        |
|------|---------|--------------|
| A    | @       | 203.0.113.10 |
| A    | vote    | 203.0.113.10 |
| A    | admin   | 203.0.113.10 |
| A    | results | 203.0.113.10 |

Check propagation from your laptop:

    dig +short example.com vote.example.com admin.example.com results.example.com

All four lines must show your IP before you request a certificate.

## 3. Install the app

    sudo useradd --system --home /opt/safevote --shell /usr/sbin/nologin safevote
    sudo mkdir -p /opt/safevote && sudo chown $USER /opt/safevote
    # copy the project into /opt/safevote (git clone, or scp the zip), then:
    cd /opt/safevote
    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
    cp .env.example .env
    python3 -c "import secrets; print(secrets.token_hex(32))"    # paste into SECRET_KEY

Edit `/opt/safevote/.env`:

    SECRET_KEY=<the value you generated>
    SERVER_NAME=example.com
    PREFERRED_URL_SCHEME=https
    TRUSTED_PROXY=1
    TIMEZONE=Africa/Nairobi

Create the first administrator and fix permissions:

    cd /opt/safevote && set -a && . ./.env && set +a
    .venv/bin/flask --app wsgi create-admin
    sudo chown -R safevote:safevote /opt/safevote/instance
    sudo chmod 600 /opt/safevote/.env && sudo chown safevote:safevote /opt/safevote/.env

Install the service:

    sudo cp deploy/safevote.service /etc/systemd/system/
    sudo systemctl daemon-reload && sudo systemctl enable --now safevote
    curl -s http://127.0.0.1:8000/healthz -H "Host: example.com"     # prints: ok

## 4. SSL certificate (6 marks)
Create the folders and install the nginx config:

    sudo mkdir -p /var/www/acme /etc/ssl/safevote /etc/nginx/snippets
    sudo cp deploy/safevote-proxy.conf /etc/nginx/snippets/
    sudo sed 's/example.com/YOURDOMAIN/g' deploy/nginx.conf | sudo tee /etc/nginx/sites-available/safevote >/dev/null

Before the certificate exists nginx will refuse the HTTPS block. Temporarily comment out the whole second `server { ... }` block (the 443 one), then:

    sudo ln -s /etc/nginx/sites-available/safevote /etc/nginx/sites-enabled/safevote
    sudo rm -f /etc/nginx/sites-enabled/default
    sudo nginx -t && sudo systemctl reload nginx

### Option A: ZeroSSL with acme.sh (automatic)

    curl https://get.acme.sh | sh -s email=you@example.com
    ~/.acme.sh/acme.sh --register-account -m you@example.com --server zerossl
    ~/.acme.sh/acme.sh --issue --server zerossl \
        -d example.com -d vote.example.com -d admin.example.com -d results.example.com \
        -w /var/www/acme
    sudo ~/.acme.sh/acme.sh --install-cert -d example.com \
        --key-file /etc/ssl/safevote/key.pem \
        --fullchain-file /etc/ssl/safevote/fullchain.pem \
        --reloadcmd "systemctl reload nginx"

### Option B: the six-month ZeroSSL trial from the dashboard
1. In the ZeroSSL dashboard create a certificate that lists all four names. Check that your trial plan allows several names on one certificate. If it allows only one, create one certificate per name and add a matching `server` block for each.
2. Verify ownership with the CNAME records ZeroSSL shows you (add them at your DNS host).
3. Download the ZIP. On the server:

       cat certificate.crt ca_bundle.crt | sudo tee /etc/ssl/safevote/fullchain.pem >/dev/null
       sudo cp private.key /etc/ssl/safevote/key.pem
       sudo chmod 600 /etc/ssl/safevote/key.pem

Now uncomment the HTTPS `server` block and reload:

    sudo nginx -t && sudo systemctl reload nginx

## 5. Verify
From your laptop:

    curl -sI http://vote.example.com | head -3          # 301 to https
    curl -sI https://vote.example.com/login | head -12  # 200 plus security headers
    curl -sI https://admin.example.com/login | head -3
    curl -sI https://results.example.com | head -3

Open each subdomain in a browser and confirm the padlock.

## 6. Operating it
- Back up the database: `sqlite3 /opt/safevote/instance/safevote.db ".backup /var/backups/safevote-$(date +%F).db"`
- Update: copy new code, then `sudo systemctl restart safevote`
- Logs: `journalctl -u safevote -f`
- Certificates: acme.sh renews on its own cron job. For the dashboard trial certificate, note the expiry date and replace it before then.
