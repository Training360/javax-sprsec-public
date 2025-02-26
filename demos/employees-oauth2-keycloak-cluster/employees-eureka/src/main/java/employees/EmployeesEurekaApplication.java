package employees;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

@SpringBootApplication
@EnableEurekaServer
public class EmployeesEurekaApplication {

	public static void main(String[] args) {
		SpringApplication.run(EmployeesEurekaApplication.class, args);
	}

}
