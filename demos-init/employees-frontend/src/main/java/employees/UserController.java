package employees;

import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

//import javax.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping
@AllArgsConstructor
@Slf4j
public class UserController {

    private Environment environment;

    @GetMapping("/user")
    public ModelAndView index() {
        Map<String, Object> model = new HashMap<>();

        return new ModelAndView("user", model);
    }

//    @GetMapping("/logout")
//    @SneakyThrows
//    public String logout(HttpServletRequest request) {
//        request.logout();
//        return "redirect:" + getAuthServerFrontendUrl() + "/protocol/openid-connect/logout?redirect_uri=" + URLEncoder.encode(getFrontendUrl(), StandardCharsets.UTF_8);
//    }

    @GetMapping("/account-console")
    public String accountConsole() {
        return "redirect:" +  getAuthServerFrontendUrl() + "/account";
    }

    private String getAuthServerFrontendUrl() {
        String prefix = environment.getProperty("employees-ui.auth-server-frontend-url");
        String realm = environment.getProperty("keycloak.realm");
        String url = prefix + "/realms/" + realm;
        return url;
    }

    private String getFrontendUrl() {
        String frontendUrl = environment.getProperty("employees-ui.frontend-url");
        return frontendUrl;
    }
}
