class: inverse, center, middle

# JWT

## &nbsp;

---

## JWT

* Saját claimeket is definiál: `iss` (Issuer), `sub` (Subject), `iat` (Issued at), `exp` (Expiration)
* JSON dokumentumok, így struktúrált adat tárolható benne
* BASE64-gyel kódolva, hiszen így adható át könnyen webes környezetben
* Három részből áll: Header, Payload, Signature

JSON Web Token (JWT) ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519))

---

## JWT

<img src="images/jwt.png" width="800" />

---

## Specifikáció gyűjtemény

* JavaScript Object Signing and Encryption (JOSE)
  * JSON Web Token (JWT) ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)): két BASE64 kódolt JSON
  * JSON Web Signature (JWS) ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)): elektronikus aláírás
  * JSON Web Encryption (JWE) ([RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)): titkosítás
  * JSON Web Algorithms (JWA) ([RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)): algoritmusok
  * JSON Web Key (JWK) ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)): kulcsok JSON formátumban

---

class: inverse, center, middle

# OAuth 2.0

## &nbsp;

---

## OAuth 2.0

* Nyílt szabány **erőforrás-hozzáférés** kezelésére (Open Authorization)
* Engedélyezésre (authorization) koncentrál, és nem a hitelesítésre (authentication)
* Fő használati területe a web, de kitér az asztali alkalmazásokra, mobil eszközökre, okos eszközökre, stb.
* **Elválik**, hogy hol történik a felhasználó hitelesítése (Authorization Server) és hol kíván erőforráshoz hozzáférni (Resource Server)
  * Google, GitHub, Facebook vagy saját szerver
* Authorization Server a hitelesítés után Access Tokent állít ki
* A Resource Server az Access Token alapján adja meg az engedélyt az adott erőforrás elérésére, pl. egy REST API-n elérhető alkalmazás
* A Client további alkalmazás, mely a felhasználó nevében próbál hozzáférni a Resource Serveren lévő erőforráshoz, pl. webalkalmazás vagy mobilalkalmazás

The OAuth 2.0 Authorization Framework ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749))

---

## Token

* Karaktersor, melynek birtokában az erőforrás elérhető
* Bearer Token, mely HTTP kéréskor a `Authorization` fejlécben küldhető át
* Opaque token: felhasználója számára nem tartalmaz információt
  * Információkat az Authorization Servertől a token birtokában a Token Introspection végponton lehet lékérni (`/token/introspect`)
* Non-opaque token: felhasználója közvetlenül ki tudja olvasni az adatot
  * Lehet JWT formátumú, JSON formátumban, BASE64-gyel kódolva

OAuth 2.0 Token Introspection ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662))

---

## OAuth 2.0 Grant Types

* Authorization Code: URL-ben az Authorization Servertől egy Authorization Code-ot kapunk, mellyel lekérhető háttérben az Access Token
* Implicit: mobil alkalmazások, vagy SPA-k használták, azonnal Access Tokent kap URL-ben (deprecated)
* Resource Owner Password Credentials: ezt olyan megbízható alkalmazások használják, melyek maguk kérik be a jelszót, nem kell átirányítás (deprecated)
* Client Credentials: ebben az esetben nem a felhasználó kerül azonosításra, hanem az alkalmazás önmaga

---

## PKCE

* Ha a támadó valamilyen módon megszerzi az Authorization Code-ot (code interception támadás), kérhet vele Access Tokent
* A PKCE egy biztonsági mechanizmus, mely plusz kódok és azok ellenőrzésével ezt kivédi
* Public client: mobil alkalmazások, SPA alkalmazások, ahol a client secret nem tárolható
  * Különösen fontos
  * Kiváltja az Implicit Grant Type-ot
* Confidental client: webes alkalmazás, client secret tárolható
  * Ennél is ajánlott
* OAuth 2.1 alapértelmezett része

Proof Key for Code Exchange by OAuth Public Clients (PKCE) ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636))

---

##  Protocol Endpoints

* Authorization Serveren
* Authorization Endpoint (`/auth`)
  * Ide történik az átirányítás, ha a felhasználó nincs bejelentkezve
  * Itt történik a hitelesítés, a szabvány nem rendelkezik, hogy hogyan
* Token Endpoint (`/token`)
  * Itt kérhetők le a tokenek

---

## Refresh token

* Access token rövid életű, hogyha a támadó megszerzi, lejárat után nem tudja használni
* Refresh token hosszú életű, segítségével új Access token kérhető
* Nem használható API hívásokban, kizárólag Access token lekérésére

---

## OAuth 2.1

* OAuth 2.0 egyszerűsített és biztonságosabb verziója
* Egyesíti az OAuth 2.0 legjobb gyakorlatait, és eltávolítja a korábban nem biztonságos vagy elavult mechanizmusokat
* Még nem végleges
* Újdonságai:
  * Implicit Flow teljes eltávolítása 
  * Resource Owner Password Credentials teljes eltávolítása
  * PKCE kötelezővé tétele minden kliens számára
  * Public client felé korlátozott Refresh token
    * Vagy Refresh Token Rotation kell
    * Vagy nem használható Refresh token
  * Access token csak HTTPS-en küldhető

---

class: inverse, center, middle

# OpenID Connect

## &nbsp;

---

## OpenID Connect 1.0 Core

* Míg az OAuth 2.0 csak az engedélyezésre koncentrál, az OpenID Connect a hitelesítésre
* OpenID Connect 1.0 egy simple identity layer az OAuth 2.0 protokoll felett
* OpenID Providernek (OP) nevezi az Authorization Servert
* Relying Party-nak (RP) nevezi a Clientet
* Flow-knak nevezi a Grant Type-okat
* Bevezeti a Identity Tokent, mely a felhasználó adatait tartalmazza
* JWT formátumban, mezői a claimek
* Szabványos claimeket definiál, mint `name` (név), `email` (email cím), stb.
* UserInfo Endpoint, melyen ezek az adatok lekérhetőek Access token használatával (`/userinfo`)

[OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

---

## OpenID Connect Discovery 1.0

* OpenID Provider Configuration Information
* `/.well-known/openid-configuration` címen egy JSON-t kell vissszaadnia az OP konfigurációjáról
  * Pl.: Publikus kulcsok címe, Authorization és Token endpoint címe, támogatott algoritmusok, stb.

[OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

---

## Logout

* [OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
  * RP kezdeményezi, átirányítással
* [Session Management](https://openid.net/specs/openid-connect-session-1_0.html)
  * RP oldalán frame-ekkel
* [OpenID Connect Front-Channel Logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
  * OP oldalán frame-ekkel
* [OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)
  * OP és RP között direkt kommunikáció
* Több RP esetén, ha biztosítani kell a kijelentkezést mindenhol, akkor a Back-Channel Logout a legmegbízhatóbb megoldás

---

## Dynamic Client Registration

* A Relying Party regisztrálhatja magát az OpenID Provideren

[OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)

---

class: inverse, center, middle

# Authorization Code Grant Type

## &nbsp;

---

## Authorization Code Grant Types lépések

<img src="images/oauth-auth-code-grant-type_1.drawio.svg" width="600"/>

---

## További paraméterek

<img src="images/oauth-auth-code-grant-type_2.drawio.svg" width="600"/>

---

## Paraméterek leírása

* Authorization Endpoint
  * `response_type=code`: Authorization Code Grant Type
  * `client_id`
  * `scope`: `openid`
  * `state`: CSRF támadás ellen, átirányítás előtt elmenti a Client (pl. session), majd visszairányításnál visszakapja és ellenőrzi (OAuth 2.0 protokoll része)
  * `redirect_uri`: milyen címre irányítson vissza
  * `nonce` (OpenID Connect része) - Client generálja, auth server beleteszi a tokenbe, amit a client ellenőrizni tud 

---

class: inverse, center, middle

# PKCE

## &nbsp;

---

## PKCE lépések

<img src="images/oauth-auth-code-grant-type_3.drawio.svg" width="600"/>

---

## PKCE paraméterek leírása

* Bejelentkezés előtt a kliens generál egy véletlen kódot: `code_verifier`
* Ebből készít egy `code_challenge`-t, SHA-256 hash algoritmussal
* Authorization Code kérésekor elküldi paraméterben, Base64 és URL encode után:
  * `code_challenge`
  * `code_challenge_method`: `S256`
* Mikor a code használatával tokent kér le, ezt is el kell küldenie `code_verifier` (form) paraméterként

