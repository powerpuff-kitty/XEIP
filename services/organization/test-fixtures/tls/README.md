# Public test certificate

`key.pem` is an intentionally public fixture key, used only by disposable loopback tests. `cert.pem` is a self-signed test certificate for `xeip.test` and `127.0.0.1`, valid for ten years from October 2026. Clients explicitly trust this certificate only for the fixture; production code never loads it by default. Never deploy this key or install it in an operating-system trust store.
