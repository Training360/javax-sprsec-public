package employees;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.event.AuthorizationEvent;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class MyAuthorizationEventHandler {

    @EventListener
    public void handle(AuthorizationEvent event) {
        log.info("Event: {}", event);
    }
}
