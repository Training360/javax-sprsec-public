package employees;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@Controller
@AllArgsConstructor
@Slf4j
public class EmployeesController {

    private EmployeesClient employeesClient;

    private EmployeesClient securedEmployeesClient;

    @GetMapping("/")
    public ModelAndView listEmployees(Principal principal, @RequestHeader HttpHeaders headers) {
        log.debug("Principal: {}", principal);
        Map<String, Object> model = new HashMap<>();
        model.put("employees", employeesClient.listEmployees());
        model.put("command", new Employee());

        return new ModelAndView("index", model);
    }

    @GetMapping("/create-employee")
    public ModelAndView createEmployee() {
        var model = Map.of(
                "command", new Employee()
        );
        return new ModelAndView("create-employee", model);
    }

    @PostMapping("/create-employee")
    public ModelAndView createEmployeePost(@ModelAttribute Employee command) {
        securedEmployeesClient.createEmployee(command);
        return new ModelAndView("redirect:/");
    }

}