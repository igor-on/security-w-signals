package org.opensearch.security.signals.watch.action.invokers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.opensearch.core.xcontent.XContentBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.codova.validation.ValidationErrors;
import org.opensearch.security.codova.validation.errors.ValidationError;
import org.opensearch.security.searchsupport.config.validation.ValidatingJsonNode;
import org.opensearch.security.signals.watch.action.handlers.ActionHandler;
import org.opensearch.security.signals.watch.checks.Check;
import org.opensearch.security.signals.watch.init.WatchInitializationService;
import org.opensearch.security.signals.watch.severity.SeverityLevel;
import org.opensearch.security.signals.watch.severity.SeverityMapping;

public class ResolveAction extends ActionInvoker {
    protected final SeverityLevel.Set resolvesSeverityLevels;

    public ResolveAction(String name, ActionHandler handler, SeverityLevel.Set resolvesSeverityLevels, List<Check> checks) {
        super(name, handler, checks, null, null);
        this.resolvesSeverityLevels = resolvesSeverityLevels;
    }

    public SeverityLevel.Set getResolvesSeverityLevels() {
        return resolvesSeverityLevels;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("type", handler.getType());

        if (name != null) {
            builder.field("name", name);
        }

        if (resolvesSeverityLevels != null) {
            builder.field("resolves_severity", resolvesSeverityLevels);
        }

        if (checks != null && checks.size() > 0) {
            builder.field("checks").startArray();

            for (Check check : checks) {
                check.toXContent(builder, params);
            }

            builder.endArray();
        }

        handler.toXContent(builder, params);

        builder.endObject();
        return builder;
    }

    public static ResolveAction create(WatchInitializationService watchInitService, ObjectNode jsonObject, SeverityMapping severityMapping)
            throws ConfigValidationException {
        ValidationErrors validationErrors = new ValidationErrors();
        ValidatingJsonNode vJsonNode = new ValidatingJsonNode(jsonObject, validationErrors);

        String name = vJsonNode.requiredString("name");
        List<Check> checks = createNestedChecks(watchInitService, vJsonNode, validationErrors);
        SeverityLevel.Set severityLevels = null;
        ActionHandler handler = null;

        try {
            severityLevels = SeverityLevel.Set.createWithNoneDisallowed(vJsonNode.requiredArray("resolves_severity"));
            validateSeverityLevelsAgainstSeverityMapping(severityLevels, severityMapping);
        } catch (ConfigValidationException e) {
            validationErrors.add("resolves_severity", e);
        }

        try {
            handler = ActionHandler.create(watchInitService, vJsonNode);
        } catch (ConfigValidationException e) {
            validationErrors.add(null, e);
        }

        vJsonNode.validateUnusedAttributes();

        validationErrors.throwExceptionForPresentErrors();

        return new ResolveAction(name, handler, severityLevels, checks);

    }

    public static List<ResolveAction> createFromArray(WatchInitializationService ctx, ArrayNode arrayNode, SeverityMapping severityMapping)
            throws ConfigValidationException {
        ValidationErrors validationErrors = new ValidationErrors();

        ArrayList<ResolveAction> result = new ArrayList<>(arrayNode.size());

        for (JsonNode member : arrayNode) {
            if (member instanceof ObjectNode) {
                try {
                    result.add(create(ctx, (ObjectNode) member, severityMapping));
                } catch (ConfigValidationException e) {
                    validationErrors.add(member.hasNonNull("name") ? "[" + member.get("name").asText() + "]" : "[]", e);
                }
            }
        }

        validationErrors.throwExceptionForPresentErrors();

        return result;
    }

    private static void validateSeverityLevelsAgainstSeverityMapping(SeverityLevel.Set severityLevels, SeverityMapping severityMapping)
            throws ConfigValidationException {        

        if (severityMapping == null) {
            throw new ConfigValidationException(new ValidationError(null, "A severity mapping is required to use resolve actions"));
        }

        if (severityLevels == null) {
            return;
        }

        Set<SeverityLevel> definedLevels = severityMapping.getDefinedLevels();

        if (!severityLevels.isSubsetOf(definedLevels)) {
            throw new ConfigValidationException(new ValidationError(null,
                    "Uses a severity which is not defined by severity mapping: " + severityLevels.missingFromOther(definedLevels)));

        }

    }

}
