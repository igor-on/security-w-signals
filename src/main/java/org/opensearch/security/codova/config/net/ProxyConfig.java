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

package org.opensearch.security.codova.config.net;

import java.util.Map;

import org.apache.http.HttpHost;
import org.apache.http.impl.client.HttpClientBuilder;

import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.codova.validation.ValidatingDocNode;
import org.opensearch.security.codova.validation.ValidationErrors;
import org.opensearch.security.codova.validation.errors.InvalidAttributeValue;

public class ProxyConfig {

    private final HttpHost host;

    public ProxyConfig(HttpHost host) {
        this.host = host;
    }

    public void apply(HttpClientBuilder httpClientBuilder) {
        if (host != null) {
            httpClientBuilder.setProxy(host);
        }
    }

    public static ProxyConfig parse(Map<String, Object> config, String property) throws ConfigValidationException {

        ValidationErrors validationErrors = new ValidationErrors();
        ValidatingDocNode vNode = new ValidatingDocNode(config, validationErrors);

        if (config.get(property) instanceof String) {
            String simpleString = (String) config.get(property);

            try {
                return new ProxyConfig(HttpHost.create(simpleString));
            } catch (IllegalArgumentException e) {
                throw new ConfigValidationException(new InvalidAttributeValue(property, "HTTP host URL", simpleString).cause(e));
            }
        } else if (vNode.hasNonNull(property + ".host")) {
            String hostName = vNode.get(property + ".host").asString();
            int port = vNode.get(property + ".port").withDefault(80).allowingNumericStrings().asInt();
            String scheme = vNode.get(property + ".scheme").withDefault("https").asString();

            validationErrors.throwExceptionForPresentErrors();

            return new ProxyConfig(new HttpHost(hostName, port, scheme));
        } else {
            return new ProxyConfig(null);
        }
    }

    public HttpHost getHost() {
        return host;
    }

    @Override
    public String toString() {
        return "ProxyConfig [host=" + host + "]";
    }
}
