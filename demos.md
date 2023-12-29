# Önálló webes alkalmazás, bejelentkezés felhasználónév és jelszó megadásával

## Alkalmazás bemutatása

* Adatbázis

```shell
docker run -d -e POSTGRES_DB=employees -e POSTGRES_USER=employees -e POSTGRES_PASSWORD=employees -p 5432:5432 --name employees-postgres postgres
```

* Felhasználói felület
* Adatbázis
* Spring Boot alkalmazás, `pom.xml`
* Liquibase
* `application.yaml`
* Felépítése: entity, repo, service, model, controller
* Thymeleaf templates
* DataSource

## Alapértelmezett bejelentkezés

* `spring-boot-starter-security`

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

* Generált jelszó a konzolon
* Elrontott bejelentkezés
* Sikeres bejelentkezés, `user` felhasználóval
* Kijelentkezés, `/logout` címen

```properties
spring.security.user.name=user
spring.security.user.password=user
```

## Felhasználók tárolása a memóriában

```java
package employees;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public UserDetailsService users() {
        var users = User.withDefaultPasswordEncoder();
        var user = users
                .username("user")
                .password("user")
                .build();
        var admin = users
                .username("admin")
                .password("admin")
                .build();
        return new InMemoryUserDetailsManager(user, admin);
    }

}
```

## Oldalak védelme URL alapján

* `@EnableWebSecurity`

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            .authorizeHttpRequests(
                    registry -> registry
                            .requestMatchers("/login")
                            .permitAll()
                            .requestMatchers("/employees")
                            .hasRole("USER")
                            .requestMatchers("/create-employee")
                            .hasRole("ADMIN")
                            .anyRequest()
                            .denyAll()
            )
            .formLogin(Customizer.withDefaults())
            .logout(Customizer.withDefaults());
    return http.build();
}
```

```java
var user = users
        .username("user")
        .password("user")
*        .authorities("ROLE_USER")
        .build();
```

## Felhasználók beolvasása JDBC-vel

```java
@Bean
public UserDetailsService users(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
}
```

```yaml
  - changeSet:
      id: 02-users.sql
      author: trainer
      changes:
        - sqlFile:
            path: 02-users.sql
            relativeToChangelogFile: true
```

```sql
create table users(username varchar(50) not null primary key,password varchar(500) not null,enabled boolean not null);
create table authorities (username varchar(50) not null,authority varchar(50) not null,constraint fk_authorities_users foreign key(username) references users(username));
create unique index ix_auth_username on authorities (username,authority);

insert into users(username, password, enabled) values ('user', 'user', true);
insert into authorities(username, authority) values ('user', 'ROLE_USER')
```

```plain
java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"
```

```java
class PasswordEncoderTest {

    @Test
    void passwordEncoder() {
        var encoder = new BCryptPasswordEncoder();
        System.out.println(encoder.encode("user"));
    }
}
```

* Érdekessége, hogy futtatásonként más értéket ad vissza.

```java
@Bean
public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
}
```

```sql
insert into users(username, password, enabled) values ('user', '$2a$10$dAT.Nf3e7V04aBsrtL5x6ebuBcSeEPBlOZ8lx3DXYCiJcviaokiDO', true);
```

# Felhasználók beolvasása JDBC-vel, saját táblaszerkezettel

* `enabled` mező helyett `is_enabled`

```sql
create table users(username varchar(50) not null primary key,password varchar(500) not null,is_enabled boolean not null);
insert into users(username, password, is_enabled) values ('user', '$2a$10$dAT.Nf3e7V04aBsrtL5x6ebuBcSeEPBlOZ8lx3DXYCiJcviaokiDO', true);
```

```java
@Bean
public UserDetailsService users(DataSource dataSource) {
        var userDetailsService = new JdbcUserDetailsManager(dataSource);
        userDetailsService.setUsersByUsernameQuery("select username,password,is_enabled from users where username = ?");
        return userDetailsService;
}
```

## Felhasználók beolvasása JPA-val

* `spring-boot-starter-data-jpa`

```java
package employees;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.List;

@Data
@Entity
@Table(name="users")
public class User implements UserDetails, Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String password;

    @ElementCollection
    @CollectionTable(name = "authorities",
            joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "authority")
    private List<String> roles;

    @Override
    public List<SimpleGrantedAuthority> getAuthorities() {
        return roles.stream().map(SimpleGrantedAuthority::new).toList();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
```

* `GrantedAuthority` - jogosultság, ennek egy implementációja: `SimpleGrantedAuthority`, String reprezentációját tárolja.
Szerepkör alapú jogosultságkezelésnél tegyük elé a `ROLE_` prefixet a String reprezentációnak.

```java
package employees;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UsersRepository extends JpaRepository<User, Long> {

    @Query("select distinct u from User u left join fetch u.roles where u.username = :username")
    Optional<User> findUserByUsername(String username);

}
```

```java
package employees;

import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@AllArgsConstructor
public class UsersService implements UserDetailsService {

    private UsersRepository usersRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return usersRepository.findUserByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Not found with username: %s".formatted(username)));
    }
}
```

`SecurityConfig`

```java
@Bean
public UserDetailsService users(UsersRepository usersRepository) {
        return new UsersService(usersRepository);
}
```

```sql
create table users (id bigserial not null primary key, password varchar(255), username varchar(255));
create unique index ix_users_username on users (username);
create table authorities (user_id bigint not null, authority varchar(255), constraint fk_authorities_users foreign key(user_id) references users(id));
create unique index ix_authorities on authorities (user_id,authority);

insert into users(username, password) values ('user', '$2a$10$dAT.Nf3e7V04aBsrtL5x6ebuBcSeEPBlOZ8lx3DXYCiJcviaokiDO');
insert into users(username, password) values ('admin', '$2a$10$zDd7RskqB5p1wRXAxRrpF.zFDYFI8d6iEbUZBjw1ZjfkeO3j8YmEO');
insert into authorities(user_id, authority) values ((select id from users where username = 'user'), 'ROLE_USER');
insert into authorities(user_id, authority) values ((select id from users where username = 'admin'), 'ROLE_USER');
insert into authorities(user_id, authority) values ((select id from users where username = 'admin'), 'ROLE_ADMIN');
```

# Actuator biztonságossá tétele külön FilterChainnel

```java
@Order(1)
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/login","/", "/create-employee", "/logout")
```

```java
@Bean
@Order(2)
public SecurityFilterChain actuatorFilterChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/actuator/**")
        .authorizeHttpRequests(
            registry -> registry
                .requestMatchers("/**")
                .hasRole("USER")
        )
        .httpBasic(Customizer.withDefaults());
    return http.build();
}
```

* Inkognitó módban tesztelhető

# Integrációs tesztelés

Függőség:

```xml
<dependency>
  <groupId>org.springframework.security</groupId>
  <artifactId>spring-security-test</artifactId>
  <scope>test</scope>
</dependency>
```

```java
@BeforeEach
void setup() {
    mockMvc = MockMvcBuilders
            .webAppContextSetup(webApplicationContext)
            .apply(springSecurity())
            .build();
}
```

```java
@Test
void notLogged() throws Exception {
    mockMvc.perform(get("/create-employee"))
            .andExpect(status().is3xxRedirection());
}
```

```java
mockMvc.perform(post("/create-employee")
                .param("name", "John Doe")
                .with(user("admin").roles("USER", "ADMIN"))
                .with(csrf()))
        .andExpect(status().is3xxRedirection());
```

# Saját bejelentkezési űrlap

* `pom.xml`

```xml
<dependency>
  <groupId>org.thymeleaf.extras</groupId>
  <artifactId>thymeleaf-extras-springsecurity6</artifactId>
</dependency>
```

* `SecurityConfig`

```java
.requestMatchers("/login")
.permitAll()
```

```java
.formLogin(conf -> conf.loginPage("/login"))
```

* `LoginController`

```java
@Controller
public class LoginController {

    @GetMapping("/login")
    public ModelAndView login() {
        return new ModelAndView("login");
    }
}
```

* `login.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Employees</title>
</head>
<body>

<div th:if="${param.error}">
    Invalid login
</div>

<div th:if="${param.logout}">
    Successful logout
</div>

<form th:action="@{login}" method="post">
    <input type="text" name="username"/>
    <input type="password" name="password"/>
    <input type="submit" value="Login"/>
</form>

</body>
</html>
```

## Kijelentkezés

```html
<form method="post" th:action="@{/logout}">
    <input type="submit" value="Logout" />
</form>
```

## Felhasználó adatainak kiírása a webes felületen

```html
xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity6"
```

```html
<p>Username: <span sec:authentication="name">Bob</span></p>
<p>Roles: <span sec:authentication="principal.authorities">[]</span></p>
```

## Link megjelenítése szerepkör alapján a webes felületen

```html
<div sec:authorize="hasRole('ADMIN')">
    <a href="/create-employee">Create employee</a>
</div>
```

## Felhasználó lekérdezése Java kódban

* `EmployeesController`

```java
@GetMapping("/")
public ModelAndView listEmployees(Principal principal) {
    log.debug("Principal: {}", principal);
```

* `EmployeesControllerIT` javítása

* Debug módban, ez egy `UsernamePasswordAuthenticationToken`, mezői:
  * `principal`: `User` típusú
  * `authorities`: `List<SimpleGrantedAuthority>`
  * `details`: `remoteAddress`, `sessionId`

```java
@GetMapping("/")
public ModelAndView listEmployees(@AuthenticationPrincipal User user) {
    log.debug("User: {}", user);
```

* Debug módban

* `EmployeesService`

```java
public List<EmployeeModel> listEmployees() {
  var authentication = SecurityContextHolder.getContext().getAuthentication();
  log.debug("Authentication: {}", authentication);
}
```

* Debug módban: `UsernamePasswordAuthenticationToken`

## Metódus szinű jogosultságkezelés

* `SecurityConfig`

```java
@EnableMethodSecurity
```

* `EmployeesService`

```java
@PreAuthorize("hasRole('ADMIN')")
public List<EmployeeModel> listEmployees() {

```

* `SecurityException`, 403 status code

```java
@PreAuthorize("hasRole('USER')")
public List<EmployeeModel> listEmployees() {

```

* További Springes annotációk: `@PreAuthorize`, `@PostAuthorize`, `@PreFilter`, `@PostFilter`, támogatják az SpEL-t
* `@EnableMethodSecurity(prePostEnabled=true)`

## Metódus szinű jogosultságkezelés integrációs tesztelése

* `EmployeesControllerIT`

```java
var user = new User();
user.setUsername("johndoe");
SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user, null));
```

```java
SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user, null,
  List.of(new SimpleGrantedAuthority("ROLE_USER"))));
```

```java
@WithMockUser(username = "johndoe")
```

```java
@WithMockUser(username = "johndoe", roles = {"USER", "ADMIN"})
```

# OAuth 2.0 és OIDC használata

## Alkalmazás bemutatása - backend

* Adatbázis

```shell
docker run -d -e POSTGRES_DB=employees -e POSTGRES_USER=employees -e POSTGRES_PASSWORD=employees -p 5432:5432 --name employees-postgres postgres
```

* Spring Boot alkalmazás, `pom.xml`
* Spring Data JPA, Spring MVC, RestController
* Alkalmazás elindítása
* SwaggerUI, `.http` file
* `application.yaml`
* Liquibase
* Felépítése: entity, repo, service, resource, controller
* Thymeleaf templates
* DataSource

## Alkalmazás bemutatása - frontend

* Spring Boot alkalmazás, `pom.xml`
* Spring Data JPA, Spring MVC, RestController
* Alkalmazás elindítása
* Felület
* `application.yaml`
* Liquibase
* Felépítése: entity, repo, service, resource, controller
* Thymeleaf templates
* DataSource

# KeyCloak indítása és konfigurálása

```shell
docker run -d -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin -p 8090:8080 --name keycloak jboss/keycloak
```

* `http://localhost:8090` címen elérhető, `admin` / `admin`
* Létre kell hozni egy Realm-et (`EmployeesRealm`)
* Létre kell hozni egy klienst, amihez meg kell adni annak azonosítóját, <br /> és hogy milyen url-en érhető el (`employees-frontend`)
    * Ellenőrizni a _Valid Redirect URIs_ értékét
* Létre kell hozni a szerepköröket (`employees_user`)
* Létre kell hozni egy felhasználót (a _Email Verified_ legyen _On_ értéken, hogy be lehessen vele jelentkezni), beállítani a jelszavát (a _Temporary_ értéke legyen _Off_, hogy ne kelljen jelszót módosítani), <br /> valamint hozzáadni a szerepkört a _Role Mappings_ fülön (`johndoe`)

## KeyCloak URL-ek

* Konfiguráció leírása

```
http://localhost:8090/auth/realms/EmployeesRealm/.well-known/openid-configuration
```

* Tanúsítványok

```
http://localhost:8090/auth/realms/EmployeesRealm/protocol/openid-connect/certs
```

* Token lekérése Resource owner password credentials használatával

```shell
curl -s --data "grant_type=password&client_id=employees-frontend&username=johndoe&password=johndoe" http://localhost:8090/auth/realms/EmployeesRealm/protocol/openid-connect/token | jq
```

```http
POST http://localhost:8090/auth/realms/EmployeesRealm/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=employees-frontend&username=johndoe&password=johndoe
```

* A https://jws.io címen ellenőrizhető

## Frontend mint Client

* Függőség:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
```

```java
package employees;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(registry -> registry
                                .requestMatchers( "/create-employee")
                .authenticated()
//                                .hasRole("employee_admin")
                                .anyRequest()
                                .permitAll()
                        )
                .oauth2Login(Customizer.withDefaults())
                .logout(conf -> conf.
                                logoutSuccessUrl("/")
                        );
        return http.build();
    }

}
```

`application.yaml`


```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            client-id: employees-frontend
            authorization-grant-type: authorization_code
            redirect-uri: http://localhost:8080/login/oauth2/code/
            scope: openid,email,profile
        provider:
          keycloak:
            issuer-uri: http://localhost:8090/auth/realms/EmployeesRealm
```

* `EmployeesController`

```java
@GetMapping("/")
public ModelAndView listEmployees(Principal principal) {
    log.debug("Principal: {}", principal);
```

`OAuth2AuthenticationToken`

* Frontend újraindítás után is bejelentkezve marad

* Logout: `http://localhost:8090/auth/realms/EmployeesRealm/protocol/openid-connect/logout?redirect_uri=http://localhost:8080`
* Account Management: `http://localhost:8090/auth/realms/EmployeesRealm/account`

## Alternatív felhasználónév használata

`application.yaml`

```yaml
spring:
  security:
    oauth2:
        provider:
          keycloak:
            user-name-attribute: preferred_username
```

## Szerepkörök átvétele

`principal` / `principal` / `idtoken`

* Client Scopes/roles/Mappers/realm roles/Add to ID token
    * A szerepkörök csak ekkor lesznek benne az id tokenbe

* `SecurityConfig`

```java
@Bean
public GrantedAuthoritiesMapper userAuthoritiesMapper() {
    return (authorities) -> authorities.stream().flatMap(authority -> {
        if (authority instanceof OidcUserAuthority oidcUserAuthority) {
            var realmAccess = (Map<String, Object>) oidcUserAuthority.getAttributes().get("realm_access");
            var roles = (List<String>)realmAccess.get("roles");


//                    OidcIdToken idToken = oidcUserAuthority.getIdToken();
//                    OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();

            // Map the claims found in idToken and/or userInfo
            // to one or more GrantedAuthority's and add it to mappedAuthorities
            return roles.stream()
                    .map(roleName -> "ROLE_" + roleName)
                    .map(SimpleGrantedAuthority::new);


        } else if (authority instanceof OAuth2UserAuthority oauth2UserAuthority) {
            Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

            // Map the attributes found in userAttributes
            // to one or more GrantedAuthority's and add it to mappedAuthorities
            return Stream.of();
        }
        else if (authority instanceof SimpleGrantedAuthority simpleGrantedAuthority) {
            return Stream.of(simpleGrantedAuthority);
        }
        else {
            throw new IllegalStateException("Invalid authority: %s".formatted(authority.getClass().getName()));
        }
    }).toList();
}
```

# Access token továbbítása a backend felé

* `SecurityConfig`

```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
        ClientRegistrationRepository clientRegistrationRepository,
        OAuth2AuthorizedClientRepository authorizedClientRepository) {

    OAuth2AuthorizedClientProvider authorizedClientProvider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                    .authorizationCode()
                    .refreshToken()
                    .clientCredentials()
                    .build();

    DefaultOAuth2AuthorizedClientManager authorizedClientManager =
            new DefaultOAuth2AuthorizedClientManager(
                    clientRegistrationRepository, authorizedClientRepository);
    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

    return authorizedClientManager;
}
```

```java
@Configuration(proxyBeanMethods = false)
public class ClientConfig {
    @Bean
    public EmployeesClient employeesClient(WebClient.Builder builder, OAuth2AuthorizedClientManager authorizedClientManager) {
        var oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        oauth2.setDefaultOAuth2AuthorizedClient(true);

        var webClient = builder
                .baseUrl("http://localhost:8081")
                .apply(oauth2.oauth2Configuration())
                .build();
        var factory = HttpServiceProxyFactory
                .builder(WebClientAdapter.forClient(webClient)).build();
        return factory.createClient(EmployeesClient.class);
    }
}
```

* Backend:

```java
@GetMapping
public List<EmployeeResource> listEmployees(@RequestHeader HttpHeaders headers) {
    log.debug("Headers: {}", headers);
    return employeesService.listEmployees();
}
```

```plain
Headers: [accept-encoding:"gzip", user-agent:"ReactorNetty/1.1.12", host:"localhost:8081", accept:"*/*", authorization:"Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICItcHJuVjJOWFk5ZjBlYnR4VDRySzdQRHo3X0NoMjc0WkhjbHVwejV6dDFZIn0.eyJleHAiOjE3MDE3MDMyMjMsImlhdCI6MTcwMTcwMjkyMywiYXV0aF90aW1lIjoxNzAxNzAxOTIxLCJqdGkiOiIyMzg1MjQzOC1hMDg0LTRjMDItODJmNi0wY2RlOGU3ODgzOTgiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwOTAvYXV0aC9yZWFsbXMvRW1wbG95ZWVzUmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNmNlNTcyNmItMDc0Mi00M2RjLWJkNDYtYjAwOWExYmFjZWI5IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZW1wbG95ZWVzLWZyb250ZW5kIiwibm9uY2UiOiIyWERGeU80ZHlXVjl1THd2WHJQU2E3U09Lb1djVjZURU44cVRBM2JBZmI0Iiwic2Vzc2lvbl9zdGF0ZSI6ImI1MDY4NmViLThkZTgtNDkxYS05MGZhLWFlZGY1NjgzOTU0NiIsImFjciI6IjAiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiIsImRlZmF1bHQtcm9sZXMtZW1wbG95ZWVzcmVhbG0iLCJlbXBsb3llZXNfdXNlciJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiJiNTA2ODZlYi04ZGU4LTQ5MWEtOTBmYS1hZWRmNTY4Mzk1NDYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwicHJlZmVycmVkX3VzZXJuYW1lIjoiam9obmRvZSJ9.NmXHCLgus0vQWnUHK2LlJeHGfBT5X_jneNHjlm9PRT6qHqMF17rMiZXuVSoLewSK3oRATg_7qYH7Gcj0jzJxG8WNeJDp9tIVngd-S_KUGggssJpxHPUDVgY_clI7uQTbhPR6bz1Ye05Pf68M9XpRPkWsin9P73vdsBJ5jOCUioob-zbEkrB7uGCA68MQsSKamdyR8anNun3fqhsqaktbnJtn65uJjIfnigmUixY70T2Ic9OVrNTSIbN8UxX5Gam-92R-Qx61AFJC57HOrVzD6CV-VrFMy7TgRfJRNBS1ty7akB8Ag-bMbSkPfj_Z1Z_f_rCUcVAUfvAq24D9ZwjaVA"]
```

# Backend mint Resource Server

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

```java
package employees;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(registry -> registry
                        .requestMatchers(HttpMethod.POST, "/api/employees")
                                .authenticated()
//                        .hasRole("employees_user")
                        .anyRequest()
                        .permitAll()
                )
                .oauth2ResourceServer(conf -> conf.jwt(Customizer.withDefaults()));
        return http.build();
    }

}
```

`application.yaml`

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8090/auth/realms/EmployeesRealm
```

* `http` fájlból a `POST` kérés: 

```json
{
  "timestamp": "2023-12-04T15:30:43.802+00:00",
  "status": 403,
  "error": "Forbidden",
  "path": "/api/employees"
}
```

```java
@GetMapping
public List<EmployeeResource> listEmployees(@RequestHeader HttpHeaders headers, Principal principal) {
    log.debug("Principal: {}", principal);

```

```plain
JwtAuthenticationToken [Principal=org.springframework.security.oauth2.jwt.Jwt@28b3d686, Credentials=[PROTECTED], Authenticated=true, Details=WebAuthenticationDetails [RemoteIpAddress=127.0.0.1, SessionId=null], Granted Authorities=[SCOPE_openid, SCOPE_profile, SCOPE_email]]
```

# Felhasználónév a backenden

```java
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;

import java.util.Collections;
import java.util.Map;

public class UsernameSubClaimAdapter implements Converter<Map<String, Object>, Map<String, Object>> {

    private final MappedJwtClaimSetConverter delegate = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

    @Override
    public Map<String, Object> convert(Map<String, Object> source) {
        Map<String, Object> convertedClaims = this.delegate.convert(source);
        String username = (String) convertedClaims.get("preferred_username");
        convertedClaims.put("sub", username);
        return convertedClaims;
    }
}
```

* `SecurityConfig`

```java
@Bean
public JwtDecoder jwtDecoderByIssuerUri(OAuth2ResourceServerProperties properties) {
    String issuerUri = properties.getJwt().getIssuerUri();
    NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(issuerUri);
    // Use preferred_username from claims as authentication name, instead of UUID subject
    jwtDecoder.setClaimSetConverter(new UsernameSubClaimAdapter());
    return jwtDecoder;
}
```

# Szerepkörök a backenden

```java
public class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        var realmAccess = (Map<String, Object>) source.getClaims().get("realm_access");
        var roles = (List<String>) realmAccess.get("roles");
        return roles.stream()
                .map(roleName -> "ROLE_" + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
```

* `SecurityConfig`

```java
@Bean
public Converter<Jwt,? extends AbstractAuthenticationToken> jwtAuthenticationConverter() {
    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    // Convert realm_access.roles claims to granted authorities, for use in access decisions
    converter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
    return converter;
}
```

# Alkalmazás clusterezése Keycloak esetén

## Eureka Service Discovery

Spring Cloud Eureka projekt létrehozása (`employees-eureka`)

* Netflix Eureka Server függőség
* `@EnableEurekaServer` annotáció

`application.yaml`

```yaml
server:
  port: 8761

spring:
  application:
    name: employees-eureka
```

`employees-frontend` projekt módosítások

* `spring-cloud-starter-netflix-eureka-client` függőség

```xml
<properties>
    <spring-cloud.version>2022.0.4</spring-cloud.version>
</properties>
```

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
</dependency>
```

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-dependencies</artifactId>
            <version>${spring-cloud.version}</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

* `application.yaml`

```yaml
spring:
  application:
    name: employees-frontend
``````

## Spring Cloud Gateway

Spring Cloud Gateway projekt létrehozása (`employees-gateway`)

* Spring Cloud Gateway
* Eureka Client

```application.yaml
server:
  port: 8084

spring:
  application:
    name: employees-gateway
  cloud:
    gateway:
      routes:
        - id: employees-frontend
          uri: lb://employees-frontend
          predicates:
            - Path=/**
```

`employees-frontend` projekt módosítások

```yaml
server:
  forward-headers-strategy: native # ez kell ahhoz, hogy ne a saját portjára, hanem a loadbalancer portjára irányítson  
spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            redirect-uri: http://localhost:8084/login/oauth2/code/ # port átírva a lb-re
```

* `EmployeesController`

```java
public ModelAndView listEmployees(Principal principal, @RequestHeader HttpHeaders headers) {
    // ...
    log.debug("Headers: {}", headers);
```

* `X-Forwarded` headerök ellenőrzése

* Átirányításkor átad egy state és egy nonce URL paramétert
    * OAuth 2.0 - átad egy `state` paramétert, melyet utána visszairányításkor URL paraméterként vissza is kap - CSRF ellen
    * OpenID Conncect - a `nonce` belekerül a tokenbe, ezzel tudja ellenőrizni a kliens, hogy a token valid

* https://stackoverflow.com/questions/18836427/how-can-i-make-spring-security-oauth2-work-with-load-balancer
* https://stackoverflow.com/questions/46844285/difference-between-oauth-2-0-state-and-openid-nonce-parameter-why-state-cou

Viszont ez állapot, sessionbe tárolja

## Session kiszervezése Redisre

```shell
docker run -d -p 6379:6379 --name redis redis
```

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.session</groupId>
    <artifactId>spring-session-data-redis</artifactId>
</dependency>
```

* `EmployeesFrontendApplication`

`@EnableRedisHttpSession`


* `application.yaml`, port átírása `8084` értékre

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            redirect-uri: http://localhost:8084/login/oauth2/code/
```

```shell
redis-cli
keys *
```

* https://xinghua24.github.io/SpringSecurity/Spring-Security-Spring-Session-Redis/
* https://docs.spring.io/spring-session/reference/2.7/spring-security.html

# Futtatás Docker Compose-zal

```shell
cd employees-backend
mvnw clean package
docker build -t employees-backend .
mvnw clean package
cd employees-frontend
docker build -t employees-frontend .
cd employees-compose
docker compose up -d
```

Sajnos a Keycloak nem támogatja azt, hogy külön frontend és backend URL-je legyen.

https://issues.redhat.com/browse/KEYCLOAK-2623

* HTTPS esetén két tanúsítvány szükséges
* URL bekerül a JWT tokenbe
* URL bekerül az e-mailbe

 Így azt javasolja, hogy `hosts` fájl
manipulációval mindig ugyanazon a címen legyen elérhető.

## Spring Authentication Server használata

`employees-auth-server` projekt

* Authorization Server függőség

`application.yaml`

```yaml
server:
  port: 9000
  servlet:
    session:
      cookie:
        name: ASSESSIONID

spring:
  jpa:
    open-in-view: false
    generate-ddl: true
    defer-datasource-initialization: true

  security:
    oauth2:
      authorizationserver:
        client:
          oidc-client:
            registration:
              client-id: "oidc-client"
              client-secret: "{noop}secret"
              client-authentication-methods:
                - "client_secret_basic"
              authorization-grant-types:
                - "client_credentials"
                - "authorization_code"
                - "refresh_token"
              redirect-uris:
                - "http://localhost:8080/login/oauth2/code/oidc-client"
              post-logout-redirect-uris:
                - "http://localhost:8080/"
              scopes:
                - "openid"
                - "profile"
            require-authorization-consent: true
```

`employees-frontend` projekt

* `application.yaml`

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          oidc-client:
            client-id: oidc-client
            client-secret: secret
            authorization-grant-type: authorization_code
            redirect-uri: http://localhost:8080/login/oauth2/code/oidc-client
            scope: openid,profile
        provider:
          oidc-client:
            issuer-uri: http://localhost:9000
```

```java
package employees;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(registry ->
                                registry
                                        .requestMatchers( "/create-employee")
                                        .authenticated()
                                        .anyRequest()
                                        .permitAll()
                )
                .oauth2Login(Customizer.withDefaults());
        return http.build();
    }

}
```

## Felhasználók perzisztálása Spring Authentication Server használatakor

* Spring Data JPA
* H2
* Lombok

```java
package training.employeesauthserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public UserDetailsService users() {
        var users = User.withDefaultPasswordEncoder();
        var user = users
                .username("user")
                .password("user")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
```