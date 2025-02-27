package employees;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.jdbc.Sql;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Sql(statements = "delete from employees")
class EmployeesControllerIT {

    @Autowired
    EmployeesController controller;

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    void create() {
//        var user = new User();
//        user.setUsername("user");
//        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user, null,
//                List.of(new SimpleGrantedAuthority("ROLE_USER"))));

        controller.createEmployeePost(new EmployeeModel("John Doe"));

        var employees = (List<EmployeeModel>) controller.listEmployees(null).getModel().get("employees");
        assertThat(employees)
                .extracting(EmployeeModel::getName)
                .containsExactly("John Doe");
    }
}
