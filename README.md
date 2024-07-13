≽(^ ᗜ ^)≼
=========

# axoloauth2

Clojure helper to fetch and refresh oauth2 tokens for desktop/cli apps
via authorization code + pkce exchange or client_credential flows.
I use it mostly for calling oauth2 protected APIs with keycloak as the
backing authorization server, via martian and a middleware that
injects the token as required.

Tokens are cached locally and refreshed if necessary. Client
configuration must allow redirect to http://localhost. Axoloauth2 opens
a local port listening for the oauth2 authorization code redirect
and then fetches the token. Uses [`(browse-url`)][https://clojuredocs.org/clojure.java.browse/browse-url],
so might not work on some systems and also not in containers.

## Configuration

By default axoloauth2 uses xdg-home and xdg-cache from babashka/fs
to load profile definitions and cache tokens, but profile and cache
locations can be customized by setting `AXOLOAUTH2_CONFIG_DIR`
and/or `AXOLOAUTH2_CACHE_DIR` respectively.

Any number of profiles are allowed, e.g. with `~/.config/axoloauth2/auth_code_example.edn`:

    {
      :auth_uri "auth-uri",
      :token_uri "token-uri",
      :client_id "client",
      :client_secret "abc",
      :scope "openid",
      :grant_type "authorization_code",
      :redirect_path "/redirect/path"
    }

The filename (without extension) is the argument you pass to `get-or-refresh-token`, 
e.g:

    (get-or-refresh-token auth_code_example :access_token)

For `client_credentials` flows use something like:

    {
     :token_uri "token-uri"
     :client_id "client"
     :client_secret "abc"
     :grant_type "client_credentials"
     }

A sample babashka script is in the project root.

## Custom Login HTML

If ~/.config/axoloauth2/login.html exists, it will be used as the login
feedback screen instead of the built-in one.

## Security

Axoloauth2 caches tokens with user read privileges if possible.
Config files contain secrets and should be guarded cautiously.
I'm still looking for a safer way to store these files.

## License

MIT License

Copyright (c) 2024 felixdo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
