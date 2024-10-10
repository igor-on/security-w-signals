package org.opensearch.security.searchsupport.config.validation;
import com.fasterxml.jackson.databind.JsonNode;
import org.opensearch.security.codova.validation.ConfigValidationException;

@FunctionalInterface
public interface JsonNodeParser<ValueType> {
    ValueType parse(JsonNode jsonNode) throws ConfigValidationException;

    default String getExpectedValue() {
        return null;
    }

}
