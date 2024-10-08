/*
 * Copyright 2020-2021 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opensearch.security.codova.validation.errors;

import java.util.LinkedHashMap;
import java.util.Map;

public class InvalidAttributeValue extends ValidationError {
    private Object expected;
    private final Object value;

    public InvalidAttributeValue(String attribute, Object value, Object expected, Object jsonNode) {
        super(attribute, "Invalid value");
        this.expected = expected;
        this.value = value;
        this.docNode(jsonNode);
    }

    public InvalidAttributeValue(String attribute, Object value, Object expected) {
        this(attribute, value, expected, null);
    }

    public Object getExpected() {
        return expected;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> result = new LinkedHashMap<>();

        result.put("error", getMessage());

        result.put("value", value);

        if (expected != null) {
            result.put("expected", expectedToString(expected));
        }

        return result;
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private static String expectedToString(Object expected) {
        if (expected == null) {
            return null;
        } else if (expected instanceof Class<?> && ((Class<?>) expected).isEnum()) {
            return getEnumValues((Class<Enum>) expected);
        } else {
            return expected.toString();
        }
    }

    private static <E extends Enum<E>> String getEnumValues(Class<E> enumClass) {
        StringBuilder result = new StringBuilder();

        for (E e : enumClass.getEnumConstants()) {
            if (result.length() > 0) {
                result.append("|");
            }

            result.append(e.name());
        }

        return result.toString();
    }

    @Override
    public String toString() {
        return "invalid value; expected: " + expectedToString(expected) + "; value: " + value + "; attribute: " + getAttribute();
    }

    @Override
    public String toValidationErrorsOverviewString() {
        return "invalid value; expected: " + expectedToString(expected);
    }

    public InvalidAttributeValue expected(Object expected) {
        this.expected = expected;
        return this;
    }

    @Override
    protected InvalidAttributeValue clone() {
        // TODO introduce generic base class to make casting not necessary
        return (InvalidAttributeValue) new InvalidAttributeValue(getAttribute(), value, expected).cause(getCause()).docNode(getDocNode())
                .message(getMessage());
    }
}