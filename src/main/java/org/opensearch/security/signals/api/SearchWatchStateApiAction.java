package org.opensearch.security.signals.api;

import static org.opensearch.common.unit.TimeValue.parseTimeValue;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;

import java.io.IOException;
import java.util.List;

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestStatusToXContentListener;
import org.opensearch.search.Scroll;
import org.opensearch.search.builder.SearchSourceBuilder;

import org.opensearch.security.filter.TenantAwareRestHandler;
import org.opensearch.security.signals.actions.watch.state.search.SearchWatchStateAction;
import org.opensearch.security.signals.actions.watch.state.search.SearchWatchStateRequest;
import org.opensearch.security.signals.actions.watch.state.search.SearchWatchStateResponse;
import com.google.common.collect.ImmutableList;

public class SearchWatchStateApiAction extends BaseRestHandler implements TenantAwareRestHandler {

    public SearchWatchStateApiAction() {

    }

    public List<Route> routes() {
        return ImmutableList.of(new Route(GET, "/_signals/watch/{tenant}/_search/_state"),
                new Route(POST, "/_signals/watch/{tenant}/_search/_state"));
    }

    @Override
    protected final RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String scroll = request.param("scroll");
        int from = request.paramAsInt("from", -1);
        int size = request.paramAsInt("size", -1);

        SearchWatchStateRequest searchWatchRequest = new SearchWatchStateRequest();

        if (scroll != null) {
            searchWatchRequest.setScroll(new Scroll(parseTimeValue(scroll, null, "scroll")));
        }

        searchWatchRequest.setFrom(from);
        searchWatchRequest.setSize(size);

        if (request.hasContent()) {
            SearchSourceBuilder searchSourceBuilder = SearchSourceBuilder.fromXContent(request.contentParser());

            searchWatchRequest.setSearchSourceBuilder(searchSourceBuilder);
        }

        return channel -> client.execute(SearchWatchStateAction.INSTANCE, searchWatchRequest,
                new RestStatusToXContentListener<SearchWatchStateResponse>(channel));

    }

    @Override
    public String getName() {
        return "Search Watch State Action";
    }
}
