package org.opensearch.security.signals.api;

import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.PUT;

import java.io.IOException;
import java.util.List;

import org.opensearch.core.action.ActionListener;
import org.opensearch.action.DocWriteResponse.Result;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.core.rest.RestStatus;

import org.opensearch.security.signals.actions.settings.get.GetSettingsAction;
import org.opensearch.security.signals.actions.settings.get.GetSettingsRequest;
import org.opensearch.security.signals.actions.settings.get.GetSettingsResponse;
import org.opensearch.security.signals.actions.settings.put.PutSettingsAction;
import org.opensearch.security.signals.actions.settings.put.PutSettingsRequest;
import org.opensearch.security.signals.actions.settings.put.PutSettingsResponse;
import com.google.common.collect.ImmutableList;

public class SettingsApiAction extends SignalsBaseRestHandler {

    public SettingsApiAction(final Settings settings, final RestController controller) {
        super(settings);
    }

    @Override
    public List<Route> routes() {
        return ImmutableList.of(new Route(GET, "/_signals/settings"), new Route(GET, "/_signals/settings/{key}"),
                new Route(PUT, "/_signals/settings/{key}"), new Route(DELETE, "/_signals/settings/{key}"));
    }

    @Override
    protected final RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        String key = request.param("key");

        switch (request.method()) {
        case GET:
            return handleGet(key, request, client);
        case PUT:
            return handlePut(key, request, client);
        case DELETE:
            return handleDelete(key, request, client);
        default:
            throw new IllegalArgumentException(request.method() + " not supported");
        }

    }

    protected RestChannelConsumer handleGet(String key, RestRequest request, Client client) throws IOException {

        return channel -> client.execute(GetSettingsAction.INSTANCE, new GetSettingsRequest(key, jsonRequested(request)),
                new ActionListener<GetSettingsResponse>() {

                    @Override
                    public void onResponse(GetSettingsResponse response) {
                        if (response.getStatus() == GetSettingsResponse.Status.OK) {
                            channel.sendResponse(new BytesRestResponse(RestStatus.OK, response.getContentType(), response.getResult()));
                        } else {
                            errorResponse(channel, RestStatus.NOT_FOUND, "Not found");
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        errorResponse(channel, e);
                    }
                });
    }

    protected RestChannelConsumer handleDelete(String key, RestRequest request, Client client) throws IOException {
        return channel -> client.execute(PutSettingsAction.INSTANCE, new PutSettingsRequest(key, null, false),
                new ActionListener<PutSettingsResponse>() {

                    @Override
                    public void onResponse(PutSettingsResponse response) {
                        if (response.getResult() == Result.CREATED || response.getResult() == Result.UPDATED
                                || response.getResult() == Result.DELETED) {

                            channel.sendResponse(
                                    new BytesRestResponse(response.getRestStatus(), convertToJson(channel, response, ToXContent.EMPTY_PARAMS)));
                        } else {
                            errorResponse(channel, response.getRestStatus(), response.getMessage(), response.getDetailJsonDocument());
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        errorResponse(channel, e);
                    }
                });
    }

    protected RestChannelConsumer handlePut(String key, RestRequest request, Client client) throws IOException {

        String content = request.content().utf8ToString();
        boolean contentIsJson = request.getXContentType() == XContentType.JSON;

        return channel -> client.execute(PutSettingsAction.INSTANCE, new PutSettingsRequest(key, content, contentIsJson),
                new ActionListener<PutSettingsResponse>() {

                    @Override
                    public void onResponse(PutSettingsResponse response) {
                        if (response.getResult() == Result.CREATED || response.getResult() == Result.UPDATED) {

                            channel.sendResponse(
                                    new BytesRestResponse(response.getRestStatus(), convertToJson(channel, response, ToXContent.EMPTY_PARAMS)));
                        } else {
                            errorResponse(channel, response.getRestStatus(), response.getMessage(), response.getDetailJsonDocument());
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        errorResponse(channel, e);
                    }
                });

    }

    protected static XContentBuilder convertToJson(RestChannel channel, ToXContent toXContent, ToXContent.Params params) {
        try {
            XContentBuilder builder = channel.newBuilder();
            toXContent.toXContent(builder, params);
            return builder;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean jsonRequested(RestRequest request) {
        String accept = request.header("Accept");

        if (accept == null) {
            return true;
        }

        String[] array = accept.split("\\s*,\\s*");

        for (String value : array) {
            if (value.startsWith("text/plain")) {
                return false;
            }
        }

        return true;
    }

    @Override
    public String getName() {
        return "Settings Action";
    }
}
