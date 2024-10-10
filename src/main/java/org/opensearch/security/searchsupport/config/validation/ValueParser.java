package org.opensearch.security.searchsupport.config.validation;

import org.opensearch.security.codova.validation.ConfigValidationException;

public interface ValueParser<ValueType> {
    ValueType parse(String string) throws ConfigValidationException;

    String getExpectedValue();
}
