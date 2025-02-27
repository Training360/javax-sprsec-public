package employees;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class PasswordEncoderTest {

    @Test
    void encode() {
        var encoder = new BCryptPasswordEncoder();
        System.out.println(encoder.encode("user"));
    }
}
