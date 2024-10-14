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

package org.opensearch.security.modules.api;

import static org.opensearch.rest.RestRequest.Method.GET;

import java.io.IOException;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.action.RestStatusToXContentListener;

import org.opensearch.security.searchsupport.client.rest.Responses;
import com.google.common.collect.ImmutableList;

public class ComponentStateRestAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(ComponentStateRestAction.class);

    public ComponentStateRestAction() {
        super();
    }

    @Override
    public List<Route> routes() {
        return ImmutableList.of(new Route(GET, "/_searchguard/component/{id}/_health"));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        if (request.method() == GET) {
            return handleGet(request.param("id"), request.paramAsBoolean("verbose", false), client);
        } else {
            return (RestChannel channel) -> Responses.sendError(channel, RestStatus.METHOD_NOT_ALLOWED, "Method not allowed: " + request.method());
        }
    }

    private RestChannelConsumer handleGet(String id, boolean verbose, NodeClient client) {
        return (RestChannel channel) -> {

            try {
                client.execute(GetComponentStateAction.INSTANCE, new GetComponentStateAction.Request(id, verbose),
                        new RestStatusToXContentListener<GetComponentStateAction.Response>(channel));
            } catch (Exception e) {
                log.error(e);
                Responses.sendError(channel, e);
            }
        };
    }

    @Override
    public String getName() {
        return "Search Guard Component Health";
    }
}
