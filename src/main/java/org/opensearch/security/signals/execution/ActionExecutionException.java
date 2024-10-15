package org.opensearch.security.signals.execution;

import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.codova.validation.ValidationErrors;
import org.opensearch.security.signals.watch.action.handlers.ActionHandler;

public class ActionExecutionException extends WatchOperationExecutionException {

    private static final long serialVersionUID = 3309028338659339298L;

    private final String actionId;

    public ActionExecutionException(ActionHandler action, String message, Throwable cause) {
        super(message, cause);
        this.actionId = action != null ? action.getName() : null;
    }

    public ActionExecutionException(ActionHandler action, Throwable cause) {
        super(cause.getMessage(), cause);
        this.actionId = action != null ? action.getName() : null;
    }

    public ActionExecutionException(ActionHandler action, String message) {
        super(message);
        this.actionId = action != null ? action.getName() : null;
    }

    public ActionExecutionException(ActionHandler action, String message, ValidationErrors validationErrors) {
        this(action, message, new ConfigValidationException(validationErrors));
    }

    public String getActionId() {
        return actionId;
    }
}
