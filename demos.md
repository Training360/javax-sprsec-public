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

```yaml
spring:
  security:
    user:
      name: user
      password: user
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

`SecurityConfig`

* `@EnableWebSecurity`

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            .authorizeHttpRequests(
                    registry -> registry
                            .requestMatchers("/login")
                            .permitAll()
                            .requestMatchers("/")
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
var admin = users
                .username("admin")
                .password("admin")
*                .authorities("ROLE_USER", "ROLE_ADMIN")
                .build();
```

## Lokalizáció

`spring-security-core.jar` `org/springframework/security/messages*.properties`

* `SecurityConfig`

```java
@Bean
public LocaleResolver localeResolver() {
    return new FixedLocaleResolver(new Locale("hu", "HU"));
}
```

Settings / Editor / File Encodings / Transparent native-to-ascii conversion 

* `src/main/resources/org/springframework/security/messages_hu.properties`

```conf
AbstractUserDetailsAuthenticationProvider.badCredentials=Hibás felhasználónév és/vagy jelszó
```

## Fejlécek

 ```plain
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Expires: 0
Pragma: no-cache
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-Xss-Protection: 0
```

* Beállítja, hogy ne legyen cache-elhető a válasz
* `X-Content-Type-Options`: böngésző ne próbálja meg kitalálni a válasz típusát (pl. jpg kiterjesztéssel JavaScriptet töltenek fel)
* `X-Frame-Options`: clickjacking, pl. a támadó a banki weboldalt egy frame-ben jeleníti meg, de elrejti, és a felhasználó nem is tudja, hogy valójában a banki oldalon klikkelget
* `X-XSS-Protection`: legacy böngészőknál volt használatos, deprecated, OWASP ajánlás 0-ra állítani. Reflected Cross site scripting (XSS) támadás ellen. Helyette már a `Content-Security-Policy` header használatos, mellyel finoman lehet szabályozni, hogy mit és honnan lehet betölteni

## 404-es oldal védelme

* Ha nincs bejelentkezve átirányít
* Ha be van jelentkezve, 403-as státusszal tér vissza

## Hibaoldal védelme

* `EmployeesController.listEmployees()` metódusban

```java
throw new IllegalStateException("Illegal state");
```

* 403

```java
.requestMatchers("/login", "/error")
.permitAll()
```

* Tegyük megjegyzésbe a hiba dobást

## Tűzfal az érvénytelen kérések kiszűrésére

* `StrictHttpFirewall` implements `HttpFirewall`

```shell
curl --path-as-is http://localhost:8080/create-employees/../admin
```

Ugyanis a böngésző és a `curl` is normalizál alapból.

```java
@Bean
public HttpFirewall httpFirewall() {
    return new StrictHttpFirewall();
}
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

## Saját annotáció felhasználó lekérdezésére

* `EmployeesController.listEmployees()`

* `Principal` paraméter esetén a `User` lekérdezésekor castolni kéne
* Működik az `Authentication` típussal is

```java
@AuthenticationPrincipal User user
```

```java
@CurrentSecurityContext(expression = "authentication.principal") User user
```

```java
@CurrentSecurityContext(expression = "authentication.principal.username") String username
```

* A `@CurrentSecurityContext` ún. meta-annotációként is használható

```java
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@CurrentSecurityContext(expression="authentication.principal.username")
public @interface CurrentUsername {
}
```

```java
@CurrentUsername String username
```

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
* `@EnableMethodSecurity`, `prePostEnabled` alapértelmezett értéke `true`

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

## Paraméterek és visszatérési értékek ellenőrzése

* `owner` mező bevezetése
  
`Employee`

```java
private String owner;

public Employee(String name, String owner) {
        this.name = name;
        this.owner = owner;
}
```

`\src\main\resources\db\db-changelog.yaml`

```yaml
  - changeSet:
      id: 03-owner
      author: trainer
      changes:
        - sqlFile:
            path: 03-owner.sql
            relativeToChangelogFile: true
```

`\src\main\resources\db\03-owner.sql`

```sql
alter table employees add owner varchar(255);

insert into users(username, password) values ('admin2', '$2a$10$zDd7RskqB5p1wRXAxRrpF.zFDYFI8d6iEbUZBjw1ZjfkeO3j8YmEO');
insert into authorities(user_id, authority) values ((select id from users where username = 'admin2'), 'ROLE_USER');
insert into authorities(user_id, authority) values ((select id from users where username = 'admin2'), 'ROLE_ADMIN');
```

`EmployeeModel`

```java
private String owner;
```

`EmployeesRepository`

```java
@Query("select new employees.EmployeeModel(e.id, e.name, e.owner) from Employee e")
```

`EmployeesService`

```java
public EmployeeModel createEmployee(EmployeeModel command, String owner) {
  var employee = new Employee(command.getName(), owner);
```

```java
private EmployeeModel toDto(Employee employee) {
    return new EmployeeModel(employee.getId(), employee.getName(), employee.getOwner());
}
```

`EmployeesController`

```java
public ModelAndView createEmployeePost(@ModelAttribute EmployeeModel command,
                                        @CurrentUsername String username) {
    employeesService.createEmployee(command, username);
    // ...
}
```

`EmployeesService`

Ez nem kerül meghívásra:

```java
@PostAuthorize("returnObject.owner == authentication.name")
public EmployeeModel findEmployeeById(long id) {
```

Ez igen:

```java
@PostFilter("filterObject.owner == authentication.name")
public List<EmployeeModel> listEmployees() {
```

## Spring Data integráció

`@PostFilter` comment

* `pom.xml`

```xml
<dependency>
  <groupId>org.springframework.security</groupId>
  <artifactId>spring-security-data</artifactId>
</dependency>
```

* `EmployeesRepository`

```java
@Query("select new employees.EmployeeModel(e.id, e.name, e.owner) from Employee e where e.owner = ?#{authentication.name}")
List<EmployeeModel> findAllResources();
```

# H2 Console önálló webes alkalmazásban

## H2 Console biztonságossá tétele külön FilterChainnel

* `pom.xml`-ben PostgreSQL, H2, `org.springframework.boot:spring-boot-devtools`
* `application.yaml`, `spring.datasource` törlése

```
org.springframework.beans.factory.UnsatisfiedDependencyException: Error creating bean with name 'org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration': Unsatisfied dependency expressed through method 'setFilterChains' parameter 0: Error creating bean with name 'filterChain' defined in class path resource [employees/SecurityConfig.class]: Failed to instantiate [org.springframework.security.web.SecurityFilterChain]: Factory method 'filterChain' threw exception with message: This method cannot decide whether these patterns are Spring MVC patterns or not. If this endpoint is a Spring MVC endpoint, please use requestMatchers(MvcRequestMatcher); otherwise, please use requestMatchers(AntPathRequestMatcher).

This is because there is more than one mappable servlet in your servlet context: {org.h2.server.web.JakartaWebServlet=[/h2-console/*], org.springframework.web.servlet.DispatcherServlet=[/]}.
```

* `SecurityConfig`

* `filterChain()` metódusban

* `HandlerMappingIntrospector` paraméter és `MvcRequestMatcher.Builder`:

```java
public SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
        var mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
}
```

```java
.securityMatcher("/**")
```

* Az összes `requestMatchers()` paramétereként

```java
.authorizeHttpRequests(
                      registry -> registry
                              .requestMatchers(mvcMatcherBuilder.pattern("/login"))
                              .permitAll()
                              .requestMatchers(mvcMatcherBuilder.pattern("/"))
                              .hasRole("USER")
                              .requestMatchers(mvcMatcherBuilder.pattern("/create-employee"))
                              .hasRole("ADMIN")
                              .requestMatchers(mvcMatcherBuilder.pattern("/error"))
                              .permitAll()
                              .anyRequest()
                              .denyAll()
              )
```

`actuatorFilterChain()` metódusban

* `HandlerMappingIntrospector` paraméter és `MvcRequestMatcher.Builder`:

```java
.requestMatchers(mvcMatcherBuilder.pattern("/**"))
```

* `h2FilterChain()` metódus

```java
@Bean
@Order(1)
public SecurityFilterChain h2FilterChain(HttpSecurity http) throws Exception {
    http
            .securityMatcher(AntPathRequestMatcher.antMatcher("/h2-console/**"))
            .authorizeHttpRequests(
                    registry -> registry
                            .requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**"))
                            .permitAll()
            )
            .csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")))
            .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
            ;

    return http.build();
}
```

* Order beállítása: `h2FilterChain`, `actuatorFilterChain`, `filterChain`

# Remember me

## Hash-Based Token

* `SecurityConfig`

```java
.rememberMe(Customizer.withDefaults())
```

* `login.html`

```html
<input type="checkbox" name="remember-me" />
```

* Bejelentkezés
* Developer Toolbar / Application / Cookies
  * `JSESSIONID` törlése
  * `remember-me`
  * `remember-me` és `JSESSIONID` törlése

## Persistent Token JDBC-vel

* `SecurityConfig`

```java
@Bean
public PersistentTokenRepository tokenRepository(DataSource dataSource) {
    var repo = new JdbcTokenRepositoryImpl();
    repo.setDataSource(dataSource);
    return repo;
}
```

```java
.rememberMe(conf -> conf.tokenRepository(tokenRepository))
```

* `db-changelog.yaml`

```yaml
  - changeSet:
      id: 04-persistence-logins
      author: trainer
      changes:
        - sqlFile:
            path: 04-persistence-logins.sql
            relativeToChangelogFile: true
```

* `03-persistence-logins.sql`

```sql
create table persistent_logins (username varchar(64) not null,
                                series varchar(64) primary key,
                                token varchar(64) not null,
                                last_used timestamp not null);
```

# Események

## Authentication events

`DefaultAuthenticationEventPublisher` dob `AuthenticationSuccessEvent` eseményt sikeres esetben,
vagy exception esetén valamely `AbstractAuthenticationFailureEvent` leszármazottat.

```java
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authorization.event.AuthorizationEvent;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class MyEventHandler {

    @EventListener
    public void handle(AbstractAuthenticationEvent event) {
        log.info("Event: {}", event);
    }
}
```

## Authorization events

* `MyAuthorizationEventHandler`

```java
@Bean
public AuthorizationEventPublisher authorizationEventPublisher(ApplicationEventPublisher eventPublisher) {
    return new SpringAuthorizationEventPublisher(eventPublisher);
}
```

```java
@EventListener
public void handle(AuthorizationEvent event) {
    log.info("Event: {}", event);
}
```

## Granted authorization events

* `MyAuthorizationEventPublisher`

```java
@Component
public class MyAuthorizationEventPublisher implements AuthorizationEventPublisher {

    private final ApplicationEventPublisher eventPublisher;

    private final AuthorizationEventPublisher authorizationEventPublisher;

    public MyAuthorizationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
        this.authorizationEventPublisher = new SpringAuthorizationEventPublisher(eventPublisher);
    }

    @Override
    public <T> void publishAuthorizationEvent(Supplier<Authentication> authentication, T object, AuthorizationDecision decision) {
        if (decision == null) {
            return;
        }
        if (!decision.isGranted()) {
            authorizationEventPublisher.publishAuthorizationEvent(authentication, object, decision);
        }
        else if (shouldThisEventBePublished(decision)) {
            AuthorizationGrantedEvent event = new AuthorizationGrantedEvent(
                    authentication, object, decision
            );
            eventPublisher.publishEvent(event);
        }
    }

    private boolean shouldThisEventBePublished(AuthorizationDecision decision) {
        if (decision instanceof AuthorityAuthorizationDecision authorityAuthorizationDecision) {
            boolean any = authorityAuthorizationDecision.getAuthorities().stream()
                    .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));
            return any;
        } else {
            return false;
        }

    }
}
```

## Audit events

* `SecurityConfig`

```java
@Bean
public AuditEventRepository auditEventRepository() {
    return new InMemoryAuditEventRepository();
}
```

* `MyEventHandler`

```java
@EventListener
public void handle(AuditApplicationEvent event) {
    log.info("Audit: {}", event);
}
```

* Actuator: http://localhost:8080/actuator

# Observability

## Tracing

* Zipkin indítása

```shell
docker run -d -p 9411:9411 --name zipkin openzipkin/zipkin
```

* `pom.xml`

```xml
<dependency>
  <groupId>io.micrometer</groupId>
  <artifactId>micrometer-tracing-bridge-brave</artifactId>
</dependency>
<dependency>
  <groupId>io.zipkin.reporter2</groupId>
  <artifactId>zipkin-reporter-brave</artifactId>
</dependency>
```

* `application.yaml`

```yaml
management:
  tracing:
    enabled: true
    sampling:
      probability: 1.0
```

* Zipkin felületén a trace-ek keresése, részletek megjelenítése: http://localhost:9411
  * filter chain
  * AuthenticationManager
  * AuthorizationManager

# HTTPS

## HTTPS PEM formátumú kulcsokkal

```shell
mkdir certs
cd certs
openssl req -x509 -subj "/CN=demo-cert-1" -keyout demo.key -out demo.crt -sha256 -days 365 -nodes -newkey rsa 
ls -la
cp * /mnt/c/trainings/employees-standalone-form-https/certs/
```

Az `openssl req` parancs ezzel a hívással egy önaláírt X.509 tanúsítványt (`.crt`) és egy hozzá tartozó privát kulcsot (`.key`) generál. Nézzük végig a paramétereket egyenként:

* `-x509`
  * Egy önaláírt (self-signed) tanúsítványt generál X.509 formátumban.
* `-subj "/CN=demo-cert-1"`
  * A tanúsítvány alanyát (subject) adja meg.
  * `CN` (Common Name) a tanúsítvány neve, itt `demo-cert-1`.
* `-keyout demo.key`
  * A privát kulcs fájlba mentését adja meg (`demo.key` fájlba kerül).
* `-out demo.crt`
  * Az elkészült tanúsítvány fájlba mentését adja meg (`demo.crt` fájlba kerül).
* `-sha256`
  * SHA-256 hash algoritmust használ a tanúsítvány aláírásához.
* `-days 365`
  * A tanúsítvány érvényességi ideje 365 nap.
* `-nodes` (no DES encryption)
  * A privát kulcs nem lesz jelszóval titkosítva.
* `-newkey rsa`
  * Egy új RSA kulcspárt generál.

* `application.yaml`

```yaml
spring:
  ssl:
    bundle:
      pem:
        demo:
          keystore:
            certificate: "certs/demo.crt"
            private-key: "certs/demo.key"

```

```yaml
server:
  ssl:
    bundle: "demo"
  port: 8443
```

```plain
2024-01-19T17:02:27.925+01:00  INFO 3184 --- [           main] o.a.t.util.net.NioEndpoint.certificate   : Connector [https-jsse-nio-8443], TLS virtual host [_default_], certificate type [UNDEFINED] configured from keystore [C:\Users\iviczian\.keystore] using alias [tomcat] with trust store [null]
```

## Kulcsok újratöltése újraindítás nélkül

Spring Boot 3.2, újratöltés

* `pom.xml`

```xml
<parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>3.2.1</version>
  <relativePath/> <!-- lookup parent from repository -->
</parent>
```

```yaml
spring:
  ssl:
    bundle:
      pem:
        demo:
*          reload-on-update: true
          keystore:
            certificate: "certs/demo.crt"
            private-key: "certs/demo.key"
```

```shell
openssl req -x509 -subj "/CN=demo-cert-2" -keyout demo.key -out demo.crt -sha256 -days 365 -nodes -newkey rsa 
cp * /mnt/c/trainings/employees-standalone-form-https/certs/
```

Csak inkognitó ablakkal működik: https://localhost:8443/

## HTTPS PKCS#12 kulcstárral

```shell
keytool -genkeypair -alias demo -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore demo.p12 -validity 3650
```

* `application.yaml`

```yaml
spring:
  ssl.bundle.jks:
    demo:
      key:
        alias: demo
      reload-on-update: true
      keystore:
        location: demo.p12
        password: changeit
        type: PKCS12
```

```yaml
server:
  ssl:
    bundle: demo
  port: 8443
```

## HTTP Strict Transport Security (HSTS)

`Strict-Transport-Security: max-age=31536000 ; includeSubDomains` header

Egy évig amennyiben kérés az adott hostra megy, mindig HTTPS-en keresztül menjen.
(Hiába van átirányítás, az első http kérést a támadók elkaphatják Man-in-the-Middle támadási móddal, és
rossz helyre irányíthatják át a felhasználó böngészőjét.)

# Cross Site Request Forgery (CSRF)

## Cross Site Request Forgery (CSRF)

Támadó az adott oldalra POST-ol. Megoldás: egyedi token generálása, és a POST esetén ellenőrzés.
Tokent valahol tárolni kell, ez alapesetben a session.

* Böngészőben login oldal
  * Alkalmazás újraindítása
  * BREACH támadás elleni védelem miatt a Spring Security minden kérésnél CSRF tokent maszkolja, véletlen értéket tesz bele. Visszaküldéskor kinyeri belőle az eredeti tokent.
* Böngészőben `/create-employee` oldal (adminként)
  * Vizsgálat, token átírása

# Content Security Policy (CSP)

## Content Security Policy (CSP)

`employees-standalone-form` -> `employees-standalone-form-csp`

Visual Studio Code / Live server

* `/page/index.html`, `/page/script.js`

```javascript
console.log("hello world")
```

* Open in Live Server `index.html`

* `employees.html`

```html
<script src="http://localhost:63342/employees-standalone-form-csp/page/script.js"></script>
```

* `SecurityConfig`

```java
.headers(headers -> headers.contentSecurityPolicy(policy -> policy.policyDirectives("script-src 'self'")))
```

```plain
Refused to load the script 'script.js' because it violates the following Content Security Policy directive:
"script-src 'self'".
```

# LDAP

## LDAP

* `pom.xml`

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<dependency>
  <groupId>com.unboundid</groupId>
  <artifactId>unboundid-ldapsdk</artifactId>
  <version>6.0.11</version>
  <scope>runtime</scope>
</dependency>

<dependency>
  <groupId>org.springframework.ldap</groupId>
  <artifactId>spring-ldap-core</artifactId>
</dependency>

<dependency>
  <groupId>org.springframework.security</groupId>
  <artifactId>spring-security-ldap</artifactId>
</dependency>
```

* `application.yaml`

```yaml
spring:
  ldap:
    embedded:
      ldif: classpath:users.ldif
      base-dn: dc=springframework,dc=org
      port: 8389
```


* `src/main/resources/users.ldif`

```ldif
dn: dc=springframework,dc=org
objectclass: top
objectclass: domain
objectclass: extensibleObject
dc: springframework

dn: ou=groups,dc=springframework,dc=org
objectclass: top
objectclass: organizationalUnit
ou: groups

dn: ou=people,dc=springframework,dc=org
objectclass: top
objectclass: organizationalUnit
ou: people

dn: uid=admin,ou=people,dc=springframework,dc=org
objectclass: top
objectclass: person
objectclass: organizationalPerson
objectclass: inetOrgPerson
uid: admin
cn: John Doe
sn: Doe
userPassword: $2a$10$zDd7RskqB5p1wRXAxRrpF.zFDYFI8d6iEbUZBjw1ZjfkeO3j8YmEO

dn: uid=user,ou=people,dc=springframework,dc=org
objectclass: top
objectclass: person
objectclass: organizationalPerson
objectclass: inetOrgPerson
uid: user
sn: Doe
cn: Jack Doe
userPassword: $2a$10$dAT.Nf3e7V04aBsrtL5x6ebuBcSeEPBlOZ8lx3DXYCiJcviaokiDO

dn: cn=user,ou=groups,dc=springframework,dc=org
objectclass: top
objectclass: groupOfUniqueNames
cn: user
uniqueMember: uid=user,ou=people,dc=springframework,dc=org
uniqueMember: uid=admin,ou=people,dc=springframework,dc=org

dn: cn=admin,ou=groups,dc=springframework,dc=org
objectclass: top
objectclass: groupOfUniqueNames
cn: admin
uniqueMember: uid=admin,ou=people,dc=springframework,dc=org
```

LDAP:

* Fa hierarchia, benne bejegyzések
* Distinguished name (DN): bejegyzés neve és helye a fában
* Object classes: milyen attribútumai lehetnek egy bejegyzésnek
* Attribute
  * CN = Common Name
  * OU = Organizational Unit
  * DC = Domain Component
  * UID = user id
  * SN = surname, vezetéknév
* LDAP data Interchange Format (LDIF)

* `SecurityConfig`

```java
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public AuthenticationManager ldapAuthenticationManager(
            BaseLdapPathContextSource contextSource, PasswordEncoder passwordEncoder, LdapAuthoritiesPopulator ldapAuthoritiesPopulator) {
        LdapPasswordComparisonAuthenticationManagerFactory  factory =
                new LdapPasswordComparisonAuthenticationManagerFactory(contextSource, passwordEncoder);
        factory.setUserDnPatterns("uid={0},ou=people,dc=springframework,dc=org");
        factory.setUserDetailsContextMapper(new PersonContextMapper());
        factory.setContextSource(contextSource);
        factory.setLdapAuthoritiesPopulator(ldapAuthoritiesPopulator);
        return factory.createAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public LdapAuthoritiesPopulator authorities(BaseLdapPathContextSource contextSource) {
        String groupSearchBase = "ou=groups,dc=springframework,dc=org";
        DefaultLdapAuthoritiesPopulator authorities =
                new DefaultLdapAuthoritiesPopulator(contextSource, groupSearchBase);
        authorities.setGroupSearchFilter("uniqueMember={0}");
        return authorities;
    }

}
```

# Backend alkalmazás bemutatása

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

# Cross-Origin Resource Sharing (CORS)

## CORS REST hívás esetén

* Böngészők lehetővé teszik bizonyos erőforrások (kép, css, stb.) elérését más
  domainről
* Biztonsági okokból azonban JavaScript AJAX hívást nem engedélyezik
    * Same-origin security policy
* Cross-origin resource sharing (CORS) egy mechanizmus arra, hogy (akár bizonyos megkötésekkel) engedélyezni lehessen
* HTTP headerekkel, böngésző oldali támogatás

`employees-backend` -> `employees-backend-cors`

```html
<h1>Employees app</h1>

<ul id="employees-ul"></ul>

<script src="js/employees.js"></script>
```

```javascript
    fetch("http://localhost:8081/api/employees")
        .then(response => response.json())
        .then(employees => {
            const ul = document.querySelector("#employees-ul")
            for (const employee of employees) {
                ul.innerHTML += `<li>${employee.name}</li>`
            }
        });
```

* `@CrossOrigin` annotáció a controller osztályon vagy metóduson
* `WebMvcConfigurer`
* Filter

```java
@Configuration(proxyBeanMethods = false)
public class WebConfiguration  implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins("*");
    }
}
```

## CORS Actuator esetén

```html
<div id="status-div"></div>
```

```javascript
fetch("http://localhost:8081/actuator/health")
.then(response => response.json())
.then(health => {
    const div = document.querySelector("#status-div");
    div.innerHTML = health.status;
});
```

```yaml
management:
  endpoints:
    web:
      cors:
        allowed-origins: '*'
```

# Backend alkalmazás JWT használatával

## Backend alkalmazás JWT használatával - bevezetés

* Felhasználónév és jelszó alapján kap egy tokent
  * Long term credential - erőforrásigényes az ellenőrzése
  * Short term credential - pl. session vagy token
* Tokent az alkalmazás állítja ki, nem authentication server
* Non-opaque token
* JSON, elektronikusan aláírva

## Basic authentication

`employees-backend` -> `employees-backend-jwt`

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

```java
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(Customizer.withDefaults())
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    @Bean
    public UserDetailsService users() {
        return new InMemoryUserDetailsManager(
                User.withUsername("user")
                        .password("{noop}user")
                        .roles("USER")
                        .build()
        );
    }

}
```

## JWT token előállítása

```java
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    // HS256 HMAC using SHA-256 hash algorithm
    // Szimmetrikus kulcsú algoritmus
    // JSON Web Key: `JWK` absztrakt ősosztály, implementációi `RSAKey`, `ECKeys`, `OctetKeyPair`, `OctetSequenceKey`, such as an AES or HMAC secret.
    private OctetSequenceKey jwk = new OctetSequenceKey.Builder(Base64URL.from("eQHD2h293EzWJtGdZ3cb2KmLV3gTxSyna-NeHKCwZ4s"))
            .build();


    @Bean
    public JwtEncoder jwtEncoder() {
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

}
```

```java
@RestController
@AllArgsConstructor
public class TokenController {

    private JwtEncoder encoder;

    @GetMapping("/token")
    public String token(Authentication authentication) {
        Instant now = Instant.now();
        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(30, ChronoUnit.MINUTES))
                .subject(authentication.getName())
                .claim("scope", scope)
                .build();
        var header = JwsHeader.with(MacAlgorithm.HS256).build();
        return this.encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
```

# JWT token beolvasása

```java
@Bean
public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withSecretKey(jwk.toSecretKey()).build();
}
```

```java
.oauth2ResourceServer(conf -> conf.jwt(Customizer.withDefaults()))
.exceptionHandling((exceptions) -> exceptions
        .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
        .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
)
```

* Listázás

```http
GET http://localhost:8081/api/employees
Accept: application/json
```

```
HTTP/1.1 401 
WWW-Authenticate: Bearer
```

* Token lekérés

```http
GET http://localhost:8081/token
Authorization: Basic user user
```

https://jwt.io/

* Token használat:

```http
GET http://localhost:8081/api/employees
Authorization: Bearer eyJraWQiOiIx...
```

# OAuth 2.0 és OIDC használata

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
docker run -d -p 8090:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin --name keycloak quay.io/keycloak/keycloak start-dev
```

* `http://localhost:8090` címen elérhető, `admin` / `admin`
* Létre kell hozni egy Realm-et (`EmployeesRealm`)
* Létre kell hozni egy klienst, amihez meg kell adni annak azonosítóját, <br /> és hogy milyen url-en érhető el (`employees-frontend`)
    * Ellenőrizni a _Valid Redirect URIs_ értékét
* Létre kell hozni a szerepköröket (`employees_user`)
* Létre kell hozni egy felhasználót (a _Email Verified_ legyen _On_ értéken, hogy be lehessen vele jelentkezni), beállítani a jelszavát (a _Temporary_ értéke legyen _Off_, hogy ne kelljen jelszót módosítani), <br /> valamint hozzáadni a szerepkört a _Role Mappings_ fülön (`johndoe`)

## KeyCloak URL-ek

> Figyelem: Az összes URL-ből eltávolítandó az `/auth` rész!

* Konfiguráció leírása

```
http://localhost:8090/realms/EmployeesRealm/.well-known/openid-configuration
```

* Tanúsítványok

```
http://localhost:8090/realms/EmployeesRealm/protocol/openid-connect/certs
```

* Token lekérése Resource owner password credentials használatával

```shell
curl -s --data "grant_type=password&client_id=employees-frontend&username=johndoe&password=johndoe" http://localhost:8090/realms/EmployeesRealm/protocol/openid-connect/token | jq
```

```http
POST http://localhost:8090/realms/EmployeesRealm/protocol/openid-connect/token
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
            issuer-uri: http://localhost:8090/realms/EmployeesRealm
```

* `EmployeesController`

```java
@GetMapping("/")
public ModelAndView listEmployees(Principal principal) {
    log.debug("Principal: {}", principal);
```

`OAuth2AuthenticationToken`

* Frontend újraindítás után is bejelentkezve marad

* Logout: `http://localhost:8090/realms/EmployeesRealm/protocol/openid-connect/logout?redirect_uri=http://localhost:8080`
* Account Management: `http://localhost:8090/realms/EmployeesRealm/account`

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

## Access token továbbítása a backend felé

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

## Access token továbbítása csak bizonyos kéréseknél

* `ClientConfig`

```java
@Bean
public EmployeesClient employeesClient(WebClient.Builder builder, EmployeesProperties employeesProperties,
                                        OAuth2AuthorizedClientManager authorizedClientManager) {
    var webClient = builder
            .baseUrl(employeesProperties.getBackendUrl())
            .build();
    var factory = HttpServiceProxyFactory
            .builder(WebClientAdapter.forClient(webClient)).build();
    return factory.createClient(EmployeesClient.class);
}

@Bean
public EmployeesClient securedEmployeesClient(WebClient.Builder builder, EmployeesProperties employeesProperties,
                                        OAuth2AuthorizedClientManager authorizedClientManager) {
    var oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
    oauth2.setDefaultOAuth2AuthorizedClient(true);

    var webClient = builder
            .baseUrl(employeesProperties.getBackendUrl())
            .apply(oauth2.oauth2Configuration())
            .build();
    var factory = HttpServiceProxyFactory
            .builder(WebClientAdapter.forClient(webClient)).build();
    return factory.createClient(EmployeesClient.class);
}
```

* `EmployeesController`

```java
    private EmployeesClient employeesClient;

    private EmployeesClient securedEmployeesClient;

    @PostMapping("/create-employee")
    public ModelAndView createEmployeePost(@ModelAttribute Employee command) {
*        securedEmployeesClient.createEmployee(command);
        return new ModelAndView("redirect:/");
    }

}
```

## Backend mint Resource Server

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
          issuer-uri: http://localhost:8090/realms/EmployeesRealm
```

* `http` fájlból a `POST` kérés meghívásakor a következő választ kapjuk: 

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

## Felhasználónév a backenden

```java
package employees;

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

## Szerepkörök a backenden

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

## Postman használata

* _Authorization_ / _OAuth 2.0_
* _Grant Type_: Password Credentials
* _Access Token URL_: `http://localhost:8080/realms/employees/protocol/openid-connect/token`
* _Client ID_: `employees-frontend`
* _Scope_: `openid`

# Scope-ok használata

Keycloak

_Client scopes_: `employees:write`, _Include in token scope_

Scope fülön: _employees_user_

_Clients_ / _employees-frontend_ / Client scopes / Add client scope (Optional) - csak akkor jelenik meg, ha explicit kérjük

Lekérés HTTP Requests-ből

`SecurityConfig`

```java
.hasAuthority("SCOPE_employees:write")
```

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            scope: openid,email,profile,employees:write
```

# PKCE

Frontend - `SecurityConfig`

```java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ClientRegistrationRepository repo) throws Exception {
        String baseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
        DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(repo, baseUri);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
      // ...

      .oauth2Login(conf -> conf.authorizationEndpoint(endpointConf -> endpointConf.authorizationRequestResolver(resolver)))

      // ...
    }
```

Böngésző DevTools, url paraméter

# Logout a Keycloak szerveren is

Frontend - `SecurityConfig`

```java
public SecurityFilterChain filterChain(HttpSecurity http, ClientRegistrationRepository repo, LogoutSuccessHandler logoutSuccessHandler) throws Exception {

  // ...

.logout(conf -> conf.logoutUrl("/logout").logoutSuccessHandler(logoutSuccessHandler));

  // ...

}
```

```java
@Bean
public LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository repo) {
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
            new OidcClientInitiatedLogoutSuccessHandler(repo);
    oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
    return oidcLogoutSuccessHandler;
}
```

# Alkalmazás clusterezése Keycloak esetén

## Eureka Service Discovery

Spring Cloud Eureka projekt létrehozása (`employees-eureka`), groupId: `training`, package: `employees`

* Netflix Eureka Server függőség
* `@EnableEurekaServer` annotáció

`application.properties`

```yaml
spring.application.name=employees-eureka
server.port=8761
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
```

## Spring Cloud Gateway

Spring Cloud Gateway projekt létrehozása (`employees-gateway`)

* Spring Cloud Gateway Reactive
* Eureka Client

```yaml
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

* `EmployeesController`

```java
public ModelAndView listEmployees(Principal principal, @RequestHeader HttpHeaders headers) {
    // ...
    log.debug("Headers: {}", headers);
```

```yaml
eureka:
  instance:
    hostname: "localhost"
```

vagy

```yaml
eureka:
  instance:
    prefer-ip-address: true
```

* `X-Forwarded` headerök ellenőrzése

Második példány elindítása `8082` porton

## Session kiszervezése Redis-re

Problémák:

* Belső átirányítások loadbalancer címek
* KeyCloak visszairányítás
* Átirányítások során különböző értékeket kell visszaellenőrizni
* Bejelentkezett felhasználó

* Átirányításkor átad egy state és egy nonce URL paramétert
    * OAuth 2.0 - átad egy `state` paramétert, melyet utána visszairányításkor URL paraméterként vissza is kap - CSRF ellen
    * OpenID Conncect - a `nonce` belekerül a tokenbe, ezzel tudja ellenőrizni a kliens, hogy a token valid

* https://stackoverflow.com/questions/18836427/how-can-i-make-spring-security-oauth2-work-with-load-balancer
* https://stackoverflow.com/questions/46844285/difference-between-oauth-2-0-state-and-openid-nonce-parameter-why-state-cou

Viszont ez állapot, sessionbe tárolja

KeyCloak megfelelő Redirect URI

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
server:
  forward-headers-strategy: native # ez kell ahhoz, hogy ne a saját portjára, hanem a loadbalancer portjára irányítson  
spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            redirect-uri: http://localhost:8084/login/oauth2/code/
```

* https://xinghua24.github.io/SpringSecurity/Spring-Security-Spring-Session-Redis/
* https://docs.spring.io/spring-session/reference/2.7/spring-security.html

# OAuth 2.0 és OIDC Spring Authorization Serverrel

## Spring Authorization Server használata

`employees-auth-server` projekt, `employees-oauth2-auth-server` könyvtárban

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
```

http://localhost:9000/.well-known/openid-configuration

http://localhost:9000/logout

## Felhasználók a Spring Authorization Serverben

* `SecurityConfig`

```java
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public UserDetailsService users() {
        return new InMemoryUserDetailsManager(
                User.withUsername("user")
                        .password("{noop}user")
                        .roles("USER")
                        .build()
        );
    }
}
```

## Frontend Spring Authorization Serverrel

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

## Constent

```yaml
            require-authorization-consent: true
```