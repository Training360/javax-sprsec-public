package employees;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.jdbc.Sql;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Sql(statements = "delete from employees")
class EmployeesControllerIT {

    @Autowired
    EmployeesController controller;

    @Test
    void create() {
        controller.createEmployeePost(new EmployeeModel("John Doe"));

        var employees = (List<EmployeeModel>) controller.listEmployees().getModel().get("employees");
        assertThat(employees)
                .extracting(EmployeeModel::getName)
                .containsExactly("John Doe");
    }
}
