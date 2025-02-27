package employees;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public UserDetailsService users(UsersRepository usersRepository) {
        return new UsersService(usersRepository);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain filterChain(HttpSecurity http, PersistentTokenRepository persistentTokenRepository) throws Exception {
        http
                .securityMatcher("/login", "/", "/create-employee", "/logout")
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
                .formLogin(conf -> conf.loginPage("/login"))
                .rememberMe(conf -> conf.tokenRepository(persistentTokenRepository))
                .logout(Customizer.withDefaults())
                .headers(headers ->
                        headers.contentSecurityPolicy(policy -> policy.policyDirectives("script-src 'self'")));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain actuatorFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/actuator/**")
                .authorizeHttpRequests(
                        registry -> registry
                                .requestMatchers("/**")
                                .authenticated()
                )
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository(DataSource dataSource) {
        var repo = new JdbcTokenRepositoryImpl();
        repo.setDataSource(dataSource);
        return repo;
    }
}
