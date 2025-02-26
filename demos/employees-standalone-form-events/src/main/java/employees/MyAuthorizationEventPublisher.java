package employees;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

@Component
public class MyAuthorizationEventPublisher implements AuthorizationEventPublisher {

    private final ApplicationEventPublisher eventPublisher;

    private final SpringAuthorizationEventPublisher delegate;

    public MyAuthorizationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
        delegate = new SpringAuthorizationEventPublisher(eventPublisher);
    }

    @Override
    public <T> void publishAuthorizationEvent(Supplier<Authentication> authentication, T object, AuthorizationDecision decision) {
        if (decision == null) {
            return;
        }
        if (!decision.isGranted()) {
            delegate.publishAuthorizationEvent(authentication, object, decision);
        }
        else if (shouldThisEventBePublished(decision)) {
            eventPublisher.publishEvent(new AuthorizationGrantedEvent<>(authentication, object, decision));
        }
    }

    private boolean shouldThisEventBePublished(AuthorizationDecision decision) {
        if (decision instanceof AuthorityAuthorizationDecision authorityAuthorizationDecision) {
            return authorityAuthorizationDecision.getAuthorities().stream()
                    .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));
        } else {
            return false;
        }

    }
}
