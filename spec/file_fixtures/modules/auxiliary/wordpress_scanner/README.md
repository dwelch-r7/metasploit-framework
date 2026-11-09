# WordPress REST captures

`responses.json` contains responses from genuine WordPress 6.8.3 / PHP 8.3.28
Apache installations and an unrelated Apache service. The disposable application
profiles use the repository's WordPress container lab; there is no simulated
WordPress response handler.

Root/subdirectory pretty REST lists, the plain-permalink query list and unrelated
HTTP came from the parent native probe in `20261109T160148-15bea4`. The pretty
route's HTTP 404 on plain permalinks, an individual author object and a refused
`context=edit` query were captured directly from the worker's real HTTP endpoints
in `20261109T160732-690ade`. Loopback ports and fixture identities are public
disposable test data. The lists contain only the actual published author.

The focused spec separately labels nulls, numbers, error-shaped objects, empty
lists and malformed rows as derived negative inputs. They are not additional
claims about responses observed from the application.
