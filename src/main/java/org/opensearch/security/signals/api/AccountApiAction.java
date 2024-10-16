package org.opensearch.security.signals.api;

import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.PUT;

import java.io.IOException;
import java.util.List;

import org.opensearch.ExceptionsHelper;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.DocWriteResponse.Result;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.core.rest.RestStatus;

import org.opensearch.security.signals.actions.account.delete.DeleteAccountAction;
import org.opensearch.security.signals.actions.account.delete.DeleteAccountRequest;
import org.opensearch.security.signals.actions.account.delete.DeleteAccountResponse;
import org.opensearch.security.signals.actions.account.get.GetAccountAction;
import org.opensearch.security.signals.actions.account.get.GetAccountRequest;
import org.opensearch.security.signals.actions.account.get.GetAccountResponse;
import org.opensearch.security.signals.actions.account.put.PutAccountAction;
import org.opensearch.security.signals.actions.account.put.PutAccountRequest;
import org.opensearch.security.signals.actions.account.put.PutAccountResponse;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

public class AccountApiAction extends SignalsBaseRestHandler {

    public AccountApiAction(final Settings settings, final RestController controller) {
        super(settings);
    }

    @Override
    public List<Route> routes() {
        return ImmutableList.of(new Route(GET, "/_signals/account/{type}/{id}"), new Route(PUT, "/_signals/account/{type}/{id}"),
                new Route(DELETE, "/_signals/account/{type}/{id}"));
    }

    @Override
    protected final RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        String accountType = request.param("type");

        if (accountType == null) {
            return channel -> errorResponse(channel, RestStatus.BAD_REQUEST, "No type specified");
        }

        String id = request.param("id");

        if (Strings.isNullOrEmpty(id)) {
            return channel -> errorResponse(channel, RestStatus.BAD_REQUEST, "No id specified");
        }

        switch (request.method()) {
        case GET:
            return handleGet(accountType, id, request, client);
        case PUT:
            return handlePut(accountType, id, request, client);
        case DELETE:
            return handleDelete(accountType, id, request, client);
        default:
            throw new IllegalArgumentException(request.method() + " not supported");
        }
    }

    protected RestChannelConsumer handleGet(String accountType, String id, RestRequest request, Client client) throws IOException {

        return channel -> client.execute(GetAccountAction.INSTANCE, new GetAccountRequest(accountType, id), new ActionListener<GetAccountResponse>() {

            @Override
            public void onResponse(GetAccountResponse response) {
                if (response.isExists()) {
                    channel.sendResponse(new BytesRestResponse(RestStatus.OK, convertToJson(channel, response, ToXContent.EMPTY_PARAMS)));
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

    protected RestChannelConsumer handleDelete(String accountType, String id, RestRequest request, Client client) throws IOException {

        return channel -> client.execute(DeleteAccountAction.INSTANCE, new DeleteAccountRequest(accountType, id),
                new ActionListener<DeleteAccountResponse>() {

                    @Override
                    public void onResponse(DeleteAccountResponse response) {
                        if (response.getResult() == DeleteAccountResponse.Result.DELETED) {
                            channel.sendResponse(new BytesRestResponse(RestStatus.OK, convertToJson(channel, response, ToXContent.EMPTY_PARAMS)));
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

    protected RestChannelConsumer handlePut(String accountType, String id, RestRequest request, Client client) throws IOException {

        // TODO: IGOR_ON CHANGE
//        if (request.getXContentType() != XContentType.JSON) {
        if (request.getMediaType() != MediaTypeRegistry.JSON) {
            return channel -> errorResponse(channel, RestStatus.UNPROCESSABLE_ENTITY, "Accounts must be of content type application/json");
        }

        BytesReference content = request.content();

        return channel -> client.execute(PutAccountAction.INSTANCE, new PutAccountRequest(accountType, id, content, XContentType.JSON),
                new ActionListener<PutAccountResponse>() {

                    @Override
                    public void onResponse(PutAccountResponse response) {
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
            throw ExceptionsHelper.convertToOpenSearchException(e);
        }
    }

    @Override
    public String getName() {
        return "Account Action";
    }

}
