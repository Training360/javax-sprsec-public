package employees;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class MyAuditEventHandler {

    @EventListener
    public void handle(AuditApplicationEvent event) {
        log.info("Audit event: {}", event);
    }
}
