# nginx deploy configs

Canonical `server{}` blocks for the reverse proxy, kept with the app so they're
version-controlled. The proxy loads configs from **its own** `conf.d` (a
Docker-mounted directory), so "deploy" means copy these in and reload. A symlink
can't cross into the nginx container, so it is a copy by necessity — this repo is
the source of truth, `conf.d` holds the deployed copy.

## Status: already wired

Both vhosts are installed in the proxy's `conf.d` and the proxy has been reloaded
(`nginx -t` passed). They reuse the existing Let's Encrypt cert
`/etc/letsencrypt/live/llm.corpberry.com/` like every other *.corpberry.com site —
Cloudflare terminates the browser TLS (proxy ON), so the origin cert name needn't
match the server_name.

They will return **502 until** (a) the app is running on `:8080`
(`docker compose up -d --build`) and (b) DNS points `corpberry.com` /
`ip.corpberry.com` at this host in Cloudflare (proxied, orange cloud).

## Re-deploying after an edit

```bash
cp deploy/nginx/*.conf /srv/my_projects/nginx-reverse-proxy/conf.d/
docker exec nginx-reverse-proxy-nginx-1 nginx -t \
  && docker exec nginx-reverse-proxy-nginx-1 nginx -s reload
```
`nginx -t` must pass before reload; a reload with a bad config is rejected and the
running config stays, so the other (client) sites on this proxy are safe.
