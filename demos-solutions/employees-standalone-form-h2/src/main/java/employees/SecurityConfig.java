package employees;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

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
    @Order(3)
    public SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
        var mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
        http
                .securityMatcher("/**")
                .authorizeHttpRequests(
                        registry -> registry
                                .requestMatchers(mvcMatcherBuilder.pattern("/login"))
                                .permitAll()
                                .requestMatchers(mvcMatcherBuilder.pattern("/"))
                                .hasRole("USER")
                                .requestMatchers(mvcMatcherBuilder.pattern("/create-employee"))
                                .hasRole("ADMIN")
                                .anyRequest()
                                .denyAll()
                )
                .formLogin(conf -> conf.loginPage("/login"))
                .logout(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain actuatorFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
        var mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
        http
                .securityMatcher("/actuator/**")
                .authorizeHttpRequests(
                        registry -> registry
                                .requestMatchers(mvcMatcherBuilder.pattern("/**"))
                                .authenticated()
                )
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

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


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
