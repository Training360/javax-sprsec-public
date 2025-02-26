package employees;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

@SpringBootApplication
@EnableRedisHttpSession
public class EmployeesFrontendApplication {

	public static void main(String[] args) {
		SpringApplication.run(EmployeesFrontendApplication.class, args);
	}

}
