/*
 * Copyright 2021 floragunn GmbH
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

package org.opensearch.security.codova.config.temporal;

import java.time.Duration;

import org.opensearch.security.codova.validation.ConfigValidationException;

public interface DurationExpression {
    Duration getActualDuration(int iteration);

    public static DurationExpression parse(String string) throws ConfigValidationException {
        if (string == null) {
            return null;
        }

        DurationExpression result = ExpontentialDurationExpression.tryParse(string);

        if (result != null) {
            return result;
        } else {
            return new ConstantDurationExpression(DurationFormat.INSTANCE.parse(string));
        }
    }
}
