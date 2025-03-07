package employees;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ClientRegistrationRepository repo, LogoutSuccessHandler logoutSuccessHandler) throws Exception {
        String baseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
        DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(repo, baseUri);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

        http
                .authorizeHttpRequests(registry -> registry
                        .requestMatchers("/create-employee")
//                        .authenticated()
//                                .hasRole("employees_user")
                                .hasAuthority("SCOPE_employees:write")
                        .anyRequest()
                        .permitAll()
                )
                .oauth2Login(conf -> conf.authorizationEndpoint(endpointConf -> endpointConf.authorizationRequestResolver(resolver)))
                .logout(conf -> conf.logoutUrl("/logout").logoutSuccessHandler(logoutSuccessHandler));
        return http.build();
    }

    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository repo) {
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(repo);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
        return oidcLogoutSuccessHandler;
    }

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

}