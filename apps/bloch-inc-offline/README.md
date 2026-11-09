# Bloch Inc offline deployment

This isolated deployment takes the `bloch-inc` Cloudflare Pages project offline.
Its advanced-mode Worker returns an empty HTTP `410 Gone` response for every
path and request method, including old pages, static assets and downloads.
Responses disable caching and request removal from search indexes.

Deploy only the `public` directory, which contains the Worker and routing
configuration. It contains no copy of the original site, documentation or
downloadable documents. The Worker never delegates to `env.ASSETS`.

```sh
wrangler pages deploy apps/bloch-inc-offline/public --project-name bloch-inc --branch main
```

The Pages project, custom domains, DNS records, deployment history and source
under `apps/bloch-inc` are preserved. Taking the site offline does not delete
historical deployment URLs. Configure preview access separately if those URLs
also need to be restricted.

Restore the site only after a separate decision to bring it online:

```sh
wrangler pages deploy apps/bloch-inc --project-name bloch-inc --branch main
```

Cloudflare documentation:
[advanced mode](https://developers.cloudflare.com/pages/functions/advanced-mode/),
[invocation routes](https://developers.cloudflare.com/pages/functions/routing/#functions-invocation-routes),
and [Direct Upload](https://developers.cloudflare.com/pages/get-started/direct-upload/).
