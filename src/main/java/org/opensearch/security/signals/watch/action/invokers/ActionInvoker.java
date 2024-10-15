package org.opensearch.security.signals.watch.action.invokers;

import java.util.Collections;
import java.util.List;

import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.ToXContent;

import com.fasterxml.jackson.databind.node.ArrayNode;
import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.codova.validation.ValidationErrors;
import org.opensearch.security.codova.validation.errors.InvalidAttributeValue;
import org.opensearch.security.searchsupport.config.validation.ValidatingJsonNode;
import org.opensearch.security.signals.execution.ActionExecutionException;
import org.opensearch.security.signals.execution.WatchExecutionContext;
import org.opensearch.security.signals.script.types.SignalsObjectFunctionScript;
import org.opensearch.security.signals.support.InlinePainlessScript;
import org.opensearch.security.signals.watch.action.handlers.ActionExecutionResult;
import org.opensearch.security.signals.watch.action.handlers.ActionHandler;
import org.opensearch.security.signals.watch.checks.Check;
import org.opensearch.security.signals.watch.init.WatchInitializationService;

public abstract class ActionInvoker implements ToXContent {
    protected final String name;
    protected final ActionHandler handler;
    protected final List<Check> checks;
    protected final InlinePainlessScript<SignalsObjectFunctionScript.Factory> foreach;
    protected final int foreachLimit;

    protected ActionInvoker(String name, ActionHandler handler, List<Check> checks, InlinePainlessScript<SignalsObjectFunctionScript.Factory> foreach,
            Integer foreachLimit) {
        this.name = name;
        this.handler = handler;
        this.checks = checks != null ? Collections.unmodifiableList(checks) : null;
        this.foreach = foreach;
        this.foreachLimit = foreachLimit != null ? foreachLimit.intValue() : 100;
    }

    public String getName() {
        return name;
    }

    public List<Check> getChecks() {
        return checks;
    }

    @Override
    public String toString() {
        return handler != null ? handler.getClass().getSimpleName() + " " + name : name;
    }

    public ActionExecutionResult execute(WatchExecutionContext ctx) throws ActionExecutionException {
        return handler.execute(ctx);
    }

    public String toJson() {
        return Strings.toString(this);
    }

    protected static List<Check> createNestedChecks(WatchInitializationService watchInitService, ValidatingJsonNode vJsonNode,
            ValidationErrors validationErrors) {
        if (vJsonNode.hasNonNull("checks")) {
            if (vJsonNode.get("checks").isArray()) {

                try {
                    return Check.create(watchInitService, (ArrayNode) vJsonNode.get("checks"));
                } catch (ConfigValidationException e) {
                    validationErrors.add("checks", e);
                }
            } else {
                validationErrors.add(new InvalidAttributeValue("checks", vJsonNode.get("checks"), "Array", vJsonNode));
            }
        }

        return Collections.emptyList();
    }

    public ActionHandler getHandler() {
        return handler;
    }

    public InlinePainlessScript<SignalsObjectFunctionScript.Factory> getForeach() {
        return foreach;
    }

    public int getForeachLimit() {
        return foreachLimit;
    }
}
