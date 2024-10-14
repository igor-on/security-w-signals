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

package org.opensearch.security.configuration.secrets;

import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.PUT;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.action.ActionType;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.StatusToXContentObject;
import org.opensearch.core.xcontent.MediaType;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.action.RestStatusToXContentListener;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import org.opensearch.security.codova.documents.DocReader;
import org.opensearch.security.codova.documents.DocType;
import org.opensearch.security.codova.documents.DocWriter;
import org.opensearch.security.searchsupport.client.rest.Responses;
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;

public class SecretsConfigApi {
    public static class GetAction extends ActionType<GetAction.Response> {
        protected final static Logger log = LogManager.getLogger(GetAction.class);

        public static final GetAction INSTANCE = new GetAction();
        public static final String NAME = "cluster:admin:searchguard:config/secret/get";

        protected GetAction() {
            super(NAME, in -> new GetAction.Response(in));
        }

        public static class Request extends ActionRequest {
            private final String id;

            public Request() {
                super();
                this.id = null;
            }

            public Request(String id) {
                super();
                this.id = id;
            }

            public Request(StreamInput in) throws IOException {
                super(in);
                this.id = in.readString();
            }

            @Override
            public void writeTo(StreamOutput out) throws IOException {
                super.writeTo(out);
                out.writeString(id);
            }

            @Override
            public ActionRequestValidationException validate() {
                return null;
            }

            public String getId() {
                return id;
            }
        }

        public static class Response extends ActionResponse implements StatusToXContentObject {

            private String id;
            private String contentJson;

            public Response() {
            }

            public Response(String id, String contentJson) {
                this.id = id;
                this.contentJson = contentJson;

            }

            public Response(StreamInput in) throws IOException {
                super(in);
                this.id = in.readString();
                this.contentJson = in.readOptionalString();
            }

            @Override
            public void writeTo(StreamOutput out) throws IOException {
                out.writeString(id);
                out.writeOptionalString(contentJson);
            }

            @Override
            public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
                if (contentJson != null) {
                    builder.rawValue(new ByteArrayInputStream(contentJson.getBytes(Charsets.UTF_8)), XContentType.JSON);
                } else {
                    builder.startObject();
                    builder.field("error", "Not found");
                    builder.endObject();
                }

                return builder;
            }

            @Override
            public RestStatus status() {
                if (contentJson != null) {
                    return RestStatus.OK;
                } else {
                    return RestStatus.NOT_FOUND;
                }
            }

        }

        public static class TransportAction extends HandledTransportAction<Request, Response> {

            private SecretsService secretsService;

            @Inject
            public TransportAction(TransportService transportService, ThreadPool threadPool, ActionFilters actionFilters,
                    SecretsService secretsService) {
                super(GetAction.NAME, transportService, actionFilters, Request::new);

                this.secretsService = secretsService;

            }

            @Override
            protected final void doExecute(Task task, Request request, ActionListener<Response> listener) {
                try {
                    Object value = secretsService.get(request.getId());

                    listener.onResponse(new Response(request.getId(), value != null ? DocWriter.json().writeAsString(value) : null));
                } catch (Exception e) {
                    listener.onFailure(e);
                }
            }
        }
    }

    public static class UpdateAction extends ActionType<UpdateAction.Response> {
        protected final static Logger log = LogManager.getLogger(UpdateAction.class);

        public static final UpdateAction INSTANCE = new UpdateAction();
        public static final String NAME = "cluster:admin:searchguard:config/secret/update";

        protected UpdateAction() {
            super(NAME, in -> new UpdateAction.Response(in));
        }

        public static class Request extends ActionRequest {
            private final String id;
            private final Object value;

            public Request(String id, Object value) {
                super();
                this.id = id;
                this.value = value;
            }

            public Request(StreamInput in) throws IOException {
                super(in);
                this.id = in.readString();
                this.value = in.readGenericValue();
            }

            @Override
            public void writeTo(StreamOutput out) throws IOException {
                super.writeTo(out);
                out.writeString(id);
                out.writeGenericValue(value);
            }

            @Override
            public ActionRequestValidationException validate() {
                return null;
            }

            public String getId() {
                return id;
            }

            public Object getValue() {
                return value;
            }
        }

        public static class Response extends ActionResponse implements StatusToXContentObject {

            private String id;
            private RestStatus restStatus;
            private String status;
            private String detailJson;

            public Response() {
            }

            public Response(String id, RestStatus restStatus, String status) {
                this.id = id;
                this.restStatus = restStatus;
                this.status = status;

            }

            public Response(String id, RestStatus restStatus, String status, String detailJson) {
                this.id = id;
                this.restStatus = restStatus;
                this.status = status;
                this.detailJson = detailJson;
            }

            public Response(StreamInput in) throws IOException {
                super(in);
                this.id = in.readString();
                this.restStatus = in.readEnum(RestStatus.class);
                this.status = in.readOptionalString();
                this.detailJson = in.readOptionalString();
            }

            @Override
            public void writeTo(StreamOutput out) throws IOException {
                out.writeString(id);
                out.writeEnum(restStatus);
                out.writeOptionalString(id);
                out.writeOptionalString(detailJson);
            }

            @Override
            public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {

                builder.startObject();

                builder.field("id", id);

                if (status != null) {
                    builder.field("status", status);
                }

                if (detailJson != null) {
                    builder.rawField("detail", new ByteArrayInputStream(detailJson.getBytes(Charsets.UTF_8)), XContentType.JSON);
                }

                builder.endObject();

                return builder;
            }

            @Override
            public RestStatus status() {
                return restStatus;
            }

        }

        public static class TransportAction extends HandledTransportAction<Request, Response> {

            private SecretsService secretsService;

            @Inject
            public TransportAction(TransportService transportService, ThreadPool threadPool, ActionFilters actionFilters,
                    SecretsService secretsService) {
                super(UpdateAction.NAME, transportService, actionFilters, Request::new);

                this.secretsService = secretsService;

            }

            @Override
            protected final void doExecute(Task task, Request request, ActionListener<Response> listener) {
                try {
                    secretsService.update(request.getId(), request.getValue(), listener);
                } catch (Exception e) {
                    log.error("Error while updating secret " + request.getId(), e);
                    listener.onFailure(e);
                }
            }
        }
    }

    public static class DeleteAction extends ActionType<DeleteAction.Response> {
        protected final static Logger log = LogManager.getLogger(DeleteAction.class);

        public static final DeleteAction INSTANCE = new DeleteAction();
        public static final String NAME = "cluster:admin:searchguard:config/secret/delete";

        protected DeleteAction() {
            super(NAME, in -> new DeleteAction.Response(in));
        }

        public static class Request extends ActionRequest {
            private final String id;

            public Request() {
                super();
                this.id = null;
            }

            public Request(String id) {
                super();
                this.id = id;
            }

            public Request(StreamInput in) throws IOException {
                super(in);
                this.id = in.readString();
            }

            @Override
            public void writeTo(StreamOutput out) throws IOException {
                super.writeTo(out);
                out.writeString(id);
            }

            @Override
            public ActionRequestValidationException validate() {
                return null;
            }

            public String getId() {
                return id;
            }
        }

        public static class Response extends ActionResponse implements StatusToXContentObject {

            private String id;
            private RestStatus restStatus;
            private String status;
            private String detailJson;

            public Response() {
            }

            public Response(String id, RestStatus restStatus, String status) {
                this.id = id;
                this.restStatus = restStatus;
                this.status = status;

            }

            public Response(String id, RestStatus restStatus, String status, String detailJson) {
                this.id = id;
                this.restStatus = restStatus;
                this.status = status;
                this.detailJson = detailJson;
            }

            public Response(StreamInput in) throws IOException {
                super(in);
                this.id = in.readString();
                this.restStatus = in.readEnum(RestStatus.class);
                this.status = in.readOptionalString();
                this.detailJson = in.readOptionalString();
            }

            @Override
            public void writeTo(StreamOutput out) throws IOException {
                out.writeString(id);
                out.writeEnum(restStatus);
                out.writeOptionalString(id);
                out.writeOptionalString(detailJson);
            }

            @Override
            public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {

                builder.startObject();

                builder.field("id", id);

                if (status != null) {
                    builder.field("status", status);
                }

                if (detailJson != null) {
                    builder.rawField("detail", new ByteArrayInputStream(detailJson.getBytes(Charsets.UTF_8)), XContentType.JSON);
                }

                builder.endObject();

                return builder;
            }

            @Override
            public RestStatus status() {
                return restStatus;
            }

        }

        public static class TransportAction extends HandledTransportAction<Request, Response> {

            private SecretsService secretsService;

            @Inject
            public TransportAction(TransportService transportService, ThreadPool threadPool, ActionFilters actionFilters,
                    SecretsService secretsService) {
                super(DeleteAction.NAME, transportService, actionFilters, Request::new);

                this.secretsService = secretsService;

            }

            @Override
            protected final void doExecute(Task task, Request request, ActionListener<Response> listener) {
                try {
                    secretsService.delete(request.getId(), listener);
                } catch (Exception e) {
                    listener.onFailure(e);
                }
            }
        }
    }

    public static class GetAllAction extends ActionType<GetAllAction.Response> {
        protected final static Logger log = LogManager.getLogger(GetAllAction.class);

        public static final GetAllAction INSTANCE = new GetAllAction();
        public static final String NAME = "cluster:admin:searchguard:config/secret/get/all";

        protected GetAllAction() {
            super(NAME, in -> new GetAllAction.Response(in));
        }

        public static class Request extends ActionRequest {
            public Request() {
                super();
            }

            public Request(String id) {
                super();
            }

            public Request(StreamInput in) throws IOException {
                super(in);
            }

            @Override
            public void writeTo(StreamOutput out) throws IOException {
                super.writeTo(out);
            }

            @Override
            public ActionRequestValidationException validate() {
                return null;
            }
        }

        public static class Response extends ActionResponse implements StatusToXContentObject {

            private String resultJson;

            public Response() {
            }

            public Response(String resultJson) {
                this.resultJson = resultJson;

            }

            public Response(StreamInput in) throws IOException {
                super(in);
                this.resultJson = in.readString();
            }

            @Override
            public void writeTo(StreamOutput out) throws IOException {
                out.writeString(resultJson);
            }

            @Override
            public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {

                builder.rawValue(new ByteArrayInputStream(resultJson.getBytes(Charsets.UTF_8)), XContentType.JSON);

                return builder;
            }

            @Override
            public RestStatus status() {
                return RestStatus.OK;
            }

        }

        public static class TransportAction extends HandledTransportAction<Request, Response> {

            private SecretsService secretsService;

            @Inject
            public TransportAction(TransportService transportService, ThreadPool threadPool, ActionFilters actionFilters,
                    SecretsService secretsService) {
                super(GetAllAction.NAME, transportService, actionFilters, Request::new);

                this.secretsService = secretsService;

            }

            @Override
            protected final void doExecute(Task task, Request request, ActionListener<Response> listener) {
                try {
                    Map<String, Object> secrets = secretsService.getAll();

                    listener.onResponse(new Response(DocWriter.json().writeAsString(secrets)));
                } catch (Exception e) {
                    listener.onFailure(e);
                }
            }
        }
    }

    public static class UpdateAllAction extends ActionType<UpdateAllAction.Response> {
        protected final static Logger log = LogManager.getLogger(UpdateAllAction.class);

        public static final UpdateAllAction INSTANCE = new UpdateAllAction();
        public static final String NAME = "cluster:admin:searchguard:config/secret/update/all";

        protected UpdateAllAction() {
            super(NAME, in -> new UpdateAllAction.Response(in));
        }

        public static class Request extends ActionRequest {
            private Map<String, Object> idToValueMap;

            public Request(Map<String, Object> idToValueMap) {
                super();
                this.idToValueMap = idToValueMap;
            }

            public Request(StreamInput in) throws IOException {
                super(in);
                this.idToValueMap = in.readMap(StreamInput::readString, StreamInput::readGenericValue);
            }

            @Override
            public void writeTo(StreamOutput out) throws IOException {
                super.writeTo(out);
                out.writeMap(idToValueMap, StreamOutput::writeString, StreamOutput::writeGenericValue);
            }

            @Override
            public ActionRequestValidationException validate() {
                return null;
            }

            public Map<String, Object> getIdToValueMap() {
                return idToValueMap;
            }

        }

        public static class Response extends ActionResponse implements StatusToXContentObject {

            private RestStatus restStatus;
            private String status;
            private String detailJson;

            public Response() {
            }

            public Response(RestStatus restStatus, String status, String detailJson) {
                this.restStatus = restStatus;
                this.status = status;

            }

            public Response(StreamInput in) throws IOException {
                super(in);
                this.restStatus = in.readEnum(RestStatus.class);
                this.status = in.readOptionalString();
                this.detailJson = in.readOptionalString();
            }

            @Override
            public void writeTo(StreamOutput out) throws IOException {
                out.writeEnum(restStatus);
                out.writeOptionalString(status);
                out.writeOptionalString(detailJson);
            }

            @Override
            public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {

                builder.startObject();

                if (status != null) {
                    builder.field("status", status);
                }

                if (detailJson != null) {
                    builder.rawField("detail", new ByteArrayInputStream(detailJson.getBytes(Charsets.UTF_8)), XContentType.JSON);
                }

                builder.endObject();

                return builder;
            }

            @Override
            public RestStatus status() {
                return restStatus;
            }

        }

        public static class TransportAction extends HandledTransportAction<Request, Response> {

            private SecretsService secretsService;

            @Inject
            public TransportAction(TransportService transportService, ThreadPool threadPool, ActionFilters actionFilters,
                    SecretsService secretsService) {
                super(UpdateAllAction.NAME, transportService, actionFilters, Request::new);

                this.secretsService = secretsService;

            }

            @Override
            protected final void doExecute(Task task, Request request, ActionListener<Response> listener) {
                try {
                    secretsService.updateAll(request.getIdToValueMap(), listener);
                } catch (Exception e) {
                    listener.onFailure(e);
                }
            }
        }
    }

    public static class RestAction extends BaseRestHandler {
        private static final Logger log = LogManager.getLogger(RestAction.class);

        public RestAction() {
            super();
        }

        @Override
        public List<Route> routes() {
            return ImmutableList.of(new Route(GET, "/_searchguard/secrets"), new Route(PUT, "/_searchguard/secrets"),
                    new Route(GET, "/_searchguard/secrets/{id}"), new Route(PUT, "/_searchguard/secrets/{id}"),
                    new Route(DELETE, "/_searchguard/secrets/{id}"));
        }

        @Override
        protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

            if (request.method() == PUT) {
                if (request.param("id") == null) {
                    return handlePutAll(request, request.requiredContent(), request.getMediaType(), client);
                } else {
                    return handlePut(request, request.param("id"), request.requiredContent(), request.getMediaType(), client);
                }
            } else if (request.method() == GET) {
                if (request.param("id") == null) {
                    return handleGetAll(request, client);
                } else {
                    return handleGet(request, request.param("id"), client);
                }
            } else if (request.method() == DELETE) {
                return handleDelete(request, request.param("id"), client);
            } else {
                return (RestChannel channel) -> Responses.sendError(channel, RestStatus.METHOD_NOT_ALLOWED,
                        "Method not allowed: " + request.method());
            }
        }

        // TODO: IGOR_ON CHANGE (XContentType to MediaType :716)
        private RestChannelConsumer handlePut(RestRequest request, String id, BytesReference body, MediaType mediaType, NodeClient client) {

            return (RestChannel channel) -> {

                try {
                    Object requestBody = DocReader.type(DocType.getByContentType(mediaType.mediaType())).read(BytesReference.toBytes(body));

                    client.execute(UpdateAction.INSTANCE, new UpdateAction.Request(id, requestBody),
                            new RestStatusToXContentListener<UpdateAction.Response>(channel));
                } catch (Exception e) {
                    log.warn("Error while handling request", e);
                    Responses.sendError(channel, e);
                }
            };
        }

        private RestChannelConsumer handleDelete(RestRequest request, String id, NodeClient client) {
            return (RestChannel channel) -> {

                try {
                    client.execute(DeleteAction.INSTANCE, new DeleteAction.Request(id),
                            new RestStatusToXContentListener<DeleteAction.Response>(channel));
                } catch (Exception e) {
                    Responses.sendError(channel, e);
                }
            };
        }

        private RestChannelConsumer handleGet(RestRequest request, String id, NodeClient client) {
            return (RestChannel channel) -> {
                try {
                    client.execute(GetAction.INSTANCE, new GetAction.Request(id), new RestStatusToXContentListener<GetAction.Response>(channel));
                } catch (Exception e) {
                    Responses.sendError(channel, e);
                }
            };
        }

        private RestChannelConsumer handleGetAll(RestRequest request, NodeClient client) {
            return (RestChannel channel) -> {
                try {
                    client.execute(GetAllAction.INSTANCE, new GetAllAction.Request(),
                            new RestStatusToXContentListener<GetAllAction.Response>(channel));
                } catch (Exception e) {
                    Responses.sendError(channel, e);
                }
            };
        }

        // TODO: IGOR_ON CHANGE (XContentType to MediaType :766)
        private RestChannelConsumer handlePutAll(RestRequest request, BytesReference body, MediaType mediaType, NodeClient client) {

            return (RestChannel channel) -> {

                try {
                    Map<String, Object> requestBody = DocReader.type(DocType.getByContentType(mediaType.mediaType()))
                            .readObject(BytesReference.toBytes(body));

                    client.execute(UpdateAllAction.INSTANCE, new UpdateAllAction.Request(requestBody),
                            new RestStatusToXContentListener<UpdateAllAction.Response>(channel));
                } catch (Exception e) {
                    log.warn("Error while handling request", e);
                    Responses.sendError(channel, e);
                }
            };
        }

        @Override
        public String getName() {
            return "Search Guard Secrets";
        }

    }

}
