# Felhasználó- és jogosultságkezelés Spring Security használatával

Ez a repository tartalmazza a tanfolyam anyagát.

A [demos.md](demos.md) fájl tartalmazza a videón szereplő feladatok leírását, bemásolható
parancsokat és forráskódrészleteket.

A `demos` könyvtár tartalmazza a videón szereplő feladatok megoldását.

* Önálló webes alkalmazás, bejelentkezés felhasználónév és jelszó megadásával (`employees-standalone-form`)
    * Alkalmazás bemutatása
    * Alapértelmezett bejelentkezés
    * Felhasználók tárolása a memóriában
    * Oldalak védelme URL alapján
    * Felhasználók beolvasása JDBC-vel
    * Felhasználók beolvasása JDBC-vel, saját táblaszerkezettel
    * Felhasználók beolvasása JPA-val
    * Felhasználók beolvasása LDAP szerverről
    * Actuator biztonságossá tétele külön FilterChainnel
    * Integrációs tesztelés
    * Saját bejelentkezési űrlap
    * Kijelentkezés
    * Felhasználó adatainak kiírása a webes felületen
    * Link megjelenítése szerepkör alapján a webes felületen
    * Felhasználó lekérdezése Java kódban
    * Metódus szinű jogosultságkezelés
    * Metódus szinű jogosultságkezelés integrációs tesztelése
* OAuth 2.0 és OIDC Keycloakkal (`employees-oauth2-keycloak`)
    * Alkalmazás bemutatása - backend
    * Alkalmazás bemutatása - frontend
    * KeyCloak indítása és konfigurálása
    * KeyCloak URL-ek
    * Frontend mint Client
    * Alternatív felhasználónév használata
    * Szerepkörök átvétele
    * Access token továbbítása a backend felé
    * Backend mint Resource Server
    * Felhasználónév a backenden
    * Szerepkörök a backenden
