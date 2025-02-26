package employees;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class MyEventHandler {

    @EventListener
    public void handle(AbstractAuthenticationEvent event) {
        log.info("Event: {}", event);
    }
}
