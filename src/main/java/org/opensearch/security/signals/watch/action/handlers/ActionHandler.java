package org.opensearch.security.signals.watch.action.handlers;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;

import org.opensearch.core.common.Strings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.codova.validation.ValidationErrors;
import org.opensearch.security.codova.validation.errors.InvalidAttributeValue;
import org.opensearch.security.codova.validation.errors.MissingAttribute;
import org.opensearch.security.searchsupport.config.validation.ValidatingJsonNode;
import org.opensearch.security.searchsupport.config.validation.ValidatingJsonParser;
import org.opensearch.security.signals.execution.ActionExecutionException;
import org.opensearch.security.signals.execution.WatchExecutionContext;
import org.opensearch.security.signals.watch.action.handlers.email.EmailAction;
import org.opensearch.security.signals.watch.action.handlers.slack.SlackAction;
import org.opensearch.security.signals.watch.common.WatchElement;
import org.opensearch.security.signals.watch.init.WatchInitializationService;

public abstract class ActionHandler extends WatchElement {

    protected ActionHandler() {

    }

    public abstract ActionExecutionResult execute(WatchExecutionContext ctx) throws ActionExecutionException;

    public abstract String getType();

    public String toJson() {
        return Strings.toString(MediaTypeRegistry.JSON, this);
    }

    public static ActionHandler create(WatchInitializationService watchInitService, ValidatingJsonNode jsonNode) throws ConfigValidationException {

        String type = null;

        if (jsonNode.hasNonNull("type")) {
            type = jsonNode.get("type").textValue();
        } else {
            throw new ConfigValidationException(new MissingAttribute("type", jsonNode));
        }

        Factory<?> factory = factoryRegistry.get(type);

        if (factory != null) {
            return factory.create(watchInitService, jsonNode);
        } else {
            throw new ConfigValidationException(new InvalidAttributeValue("type", type, factoryRegistry.getFactoryNames(), jsonNode));
        }
    }

    public static ActionHandler create(WatchInitializationService watchInitService, JsonNode jsonNode) throws ConfigValidationException {

        String type = null;

        if (jsonNode.hasNonNull("type")) {
            type = jsonNode.get("type").textValue();
        } else {
            throw new ConfigValidationException(new MissingAttribute("type", jsonNode));
        }

        Factory<?> factory = factoryRegistry.get(type);

        if (factory != null) {
            return factory.create(watchInitService, jsonNode);
        } else {
            throw new ConfigValidationException(new InvalidAttributeValue("type", type, factoryRegistry.getFactoryNames(), jsonNode));
        }
    }

    public static ActionHandler parseJson(WatchInitializationService ctx, String json) throws ConfigValidationException {
        JsonNode jsonNode = ValidatingJsonParser.readTree(json);

        return create(ctx, (ObjectNode) jsonNode);
    }

    public static abstract class Factory<A extends ActionHandler> {
        private final String type;

        protected Factory(String type) {
            this.type = type;
        }

        public final A create(WatchInitializationService watchInitService, JsonNode jsonNode) throws ConfigValidationException {
            ValidationErrors validationErrors = new ValidationErrors();
            ValidatingJsonNode vJsonNode = new ValidatingJsonNode(jsonNode, validationErrors);

            A result = create(watchInitService, vJsonNode, validationErrors);

            validationErrors.throwExceptionForPresentErrors();

            return result;
        }

        public final A create(WatchInitializationService watchInitService, ValidatingJsonNode vJsonNode) throws ConfigValidationException {
            ValidationErrors validationErrors = new ValidationErrors();
            vJsonNode = new ValidatingJsonNode(vJsonNode, validationErrors);

            A result = create(watchInitService, vJsonNode, validationErrors);

            validationErrors.throwExceptionForPresentErrors();

            return result;
        }

        protected abstract A create(WatchInitializationService watchInitService, ValidatingJsonNode vJsonNode, ValidationErrors validationErrors)
                throws ConfigValidationException;

        public String getType() {
            return type;
        }
    }

    public static final class FactoryRegistry {
        private final Map<String, Factory<?>> factories = new HashMap<>();
        private String factoryNames;

        FactoryRegistry(ActionHandler.Factory<?>... factories) {
            add(factories);
        }

        private void internalAddFactory(ActionHandler.Factory<?> factory) {
            if (factory.getType() == null) {
                throw new IllegalArgumentException("type of factory is null: " + factory);
            }

            if (factories.containsKey(factory.getType())) {
                throw new IllegalStateException("Factory of type " + factory.getType() + " (" + factory + ") was already installed: " + factories);
            }

            factories.put(factory.getType().toLowerCase(), factory);
        }

        public void add(ActionHandler.Factory<?>... factories) {
            for (Factory<?> factory : factories) {
                internalAddFactory(factory);
            }

            factoryNames = String.join("|", new TreeSet<>(this.factories.keySet()));
        }

        public Factory<?> get(String type) {
            return factories.get(type.toLowerCase());
        }

        String getFactoryNames() {
            return factoryNames;
        }
    }

    public static final FactoryRegistry factoryRegistry = new FactoryRegistry(new IndexAction.Factory(), new WebhookAction.Factory(),
            new EmailAction.Factory(), new SlackAction.Factory());

}
