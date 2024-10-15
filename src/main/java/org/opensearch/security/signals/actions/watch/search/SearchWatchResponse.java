package org.opensearch.security.signals.actions.watch.search;

import java.io.IOException;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.StatusToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.rest.RestStatus;

import org.opensearch.security.signals.watch.Watch;

public class SearchWatchResponse extends ActionResponse implements StatusToXContentObject {

    private SearchResponse searchResponse;

    public SearchWatchResponse() {
    }

    public SearchWatchResponse(SearchResponse searchResponse) {
        this.searchResponse = searchResponse;
    }

    public SearchWatchResponse(StreamInput in) throws IOException {
        super(in);
        this.searchResponse = new SearchResponse(in);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        this.searchResponse.writeTo(out);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        this.searchResponse.toXContent(builder, new DelegatingMapParams(Watch.WITHOUT_AUTH_TOKEN_PARAM_MAP, params));
        return builder;
    }

    public SearchResponse getSearchResponse() {
        return searchResponse;
    }

    @Override
    public RestStatus status() {
        return searchResponse.status();
    }

}
