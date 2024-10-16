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
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.core.rest.RestStatus;

import org.opensearch.security.filter.TenantAwareRestHandler;
import org.opensearch.security.signals.actions.watch.delete.DeleteWatchAction;
import org.opensearch.security.signals.actions.watch.delete.DeleteWatchRequest;
import org.opensearch.security.signals.actions.watch.delete.DeleteWatchResponse;
import org.opensearch.security.signals.actions.watch.get.GetWatchAction;
import org.opensearch.security.signals.actions.watch.get.GetWatchRequest;
import org.opensearch.security.signals.actions.watch.get.GetWatchResponse;
import org.opensearch.security.signals.actions.watch.put.PutWatchAction;
import org.opensearch.security.signals.actions.watch.put.PutWatchRequest;
import org.opensearch.security.signals.actions.watch.put.PutWatchResponse;
import org.opensearch.security.signals.watch.Watch;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

public class WatchApiAction extends SignalsBaseRestHandler implements TenantAwareRestHandler {

    public WatchApiAction(final Settings settings) {
        super(settings);
    }

    @Override
    public List<Route> routes() {
        return ImmutableList.of(new Route(GET, "/_signals/watch/{tenant}/{id}"), new Route(PUT, "/_signals/watch/{tenant}/{id}"),
                new Route(DELETE, "/_signals/watch/{tenant}/{id}"));
    }

    @Override
    protected final RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        String id = request.param("id");

        if (Strings.isNullOrEmpty(id)) {
            return channel -> errorResponse(channel, RestStatus.BAD_REQUEST, "No id specified");
        }

        switch (request.method()) {
        case GET:
            return handleGet(id, request, client);
        case PUT:
            return handlePut(id, request, client);
        case DELETE:
            return handleDelete(id, request, client);
        default:
            throw new IllegalArgumentException(request.method() + " not supported");
        }
    }

    protected RestChannelConsumer handleGet(String id, RestRequest request, Client client) throws IOException {

        return channel -> client.execute(GetWatchAction.INSTANCE, new GetWatchRequest(id), new ActionListener<GetWatchResponse>() {

            @Override
            public void onResponse(GetWatchResponse response) {
                if (response.isExists()) {
                    channel.sendResponse(new BytesRestResponse(RestStatus.OK, convertToJson(channel, response, Watch.WITHOUT_AUTH_TOKEN)));
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

    protected RestChannelConsumer handleDelete(String id, RestRequest request, Client client) throws IOException {

        return channel -> client.execute(DeleteWatchAction.INSTANCE, new DeleteWatchRequest(id), new ActionListener<DeleteWatchResponse>() {

            @Override
            public void onResponse(DeleteWatchResponse response) {
                if (response.getResult() == Result.DELETED) {
                    channel.sendResponse(new BytesRestResponse(RestStatus.OK, convertToJson(channel, response, Watch.WITHOUT_AUTH_TOKEN)));
                } else {
                    errorResponse(channel, response.getRestStatus(), response.getMessage());
                }
            }

            @Override
            public void onFailure(Exception e) {
                errorResponse(channel, e);
            }
        });

    }

    protected RestChannelConsumer handlePut(String id, RestRequest request, Client client) throws IOException {

        // TODO: IGOR_ON CHANGE
//        if (request.getXContentType() != XContentType.JSON) {
        if (request.getMediaType() != MediaTypeRegistry.JSON) {
            return channel -> errorResponse(channel, RestStatus.UNSUPPORTED_MEDIA_TYPE, "Watches must be of content type application/json");
        }

        BytesReference content = request.content();

        return channel -> client.execute(PutWatchAction.INSTANCE, new PutWatchRequest(id, content, XContentType.JSON),
                new ActionListener<PutWatchResponse>() {

                    @Override
                    public void onResponse(PutWatchResponse response) {
                        if (response.getResult() == Result.CREATED || response.getResult() == Result.UPDATED) {

                            channel.sendResponse(
                                    new BytesRestResponse(response.getRestStatus(), convertToJson(channel, response, Watch.WITHOUT_AUTH_TOKEN)));
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

    @Override
    public String getName() {
        return "Watch Action";
    }

}
