package org.opensearch.security.support;

/*
 * Copyright 2020 floragunn GmbH
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

import org.opensearch.client.Client;

import org.opensearch.security.internalauthtoken.InternalAuthTokenProvider;
import org.opensearch.security.searchsupport.client.ContextHeaderDecoratorClient;

public class PrivilegedConfigClient extends ContextHeaderDecoratorClient {

    public PrivilegedConfigClient(Client in) {
        super(in, ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true", InternalAuthTokenProvider.TOKEN_HEADER, "",
                InternalAuthTokenProvider.AUDIENCE_HEADER, "");
    }

    public static PrivilegedConfigClient adapt(Client client) {
        if (client instanceof PrivilegedConfigClient) {
            return (PrivilegedConfigClient) client;
        } else {
            return new PrivilegedConfigClient(client);
        }
    }
}
