package org.opensearch.security.signals.confconv.es;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.opensearch.security.codova.validation.ValidationErrors;
import org.opensearch.security.codova.validation.errors.InvalidAttributeValue;
import org.opensearch.security.searchsupport.json.JacksonTools;
import org.opensearch.security.signals.confconv.ConversionResult;
import org.opensearch.security.signals.watch.checks.Check;
import org.opensearch.security.signals.watch.checks.StaticInput;

public class MetaConverter {

    private final JsonNode metaJsonNode;

    public MetaConverter(JsonNode metaJsonNode) {
        this.metaJsonNode = metaJsonNode;
    }

    ConversionResult<List<Check>> convertToSignals() {
        ValidationErrors validationErrors = new ValidationErrors();
        List<Check> result = new ArrayList<>();

        if (!(metaJsonNode instanceof ObjectNode)) {
            validationErrors.add(new InvalidAttributeValue(null, metaJsonNode, "JSON object"));
            return new ConversionResult<List<Check>>(result, validationErrors);

        }
        
        ObjectNode metaObjectNode = (ObjectNode) metaJsonNode;
        
        result.add(new StaticInput("_imported_metadata", "_top", JacksonTools.toMap(metaObjectNode)));
        
        return new ConversionResult<List<Check>>(result, validationErrors);
    }

}
