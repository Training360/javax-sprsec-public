package employees;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@SpringBootTest
@Sql(statements = "delete from employees")
class EmployeesControllerMockMvcIT {

    @Autowired
    WebApplicationContext webApplicationContext;

    MockMvc mockMvc;

    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(webApplicationContext)
                .build();
    }

    @Test
    void createEmployee() throws Exception {
        mockMvc.perform(post("/create-employee")
                        .param("name", "John Doe"))
                .andExpect(status().is3xxRedirection())
                        .andExpect(header().string("location", "/"));


        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("employees"))
                .andExpect(model().attribute("employees",
                        hasItem(hasProperty("name", equalTo("John Doe")))))
                .andExpect(content().string(containsString("John Doe")));
    }



}
