package org.opensearch.security.signals.actions.watch.search;

import org.opensearch.action.ActionType;

public class SearchWatchAction extends ActionType<SearchWatchResponse> {

    public static final SearchWatchAction INSTANCE = new SearchWatchAction();
    public static final String NAME = "cluster:admin:searchguard:tenant:signals:watch/search";

    protected SearchWatchAction() {
        super(NAME, in -> {
            SearchWatchResponse response = new SearchWatchResponse(in);
            return response;
        });
    }
}
