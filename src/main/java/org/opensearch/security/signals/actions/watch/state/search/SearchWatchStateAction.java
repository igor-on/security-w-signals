package org.opensearch.security.signals.actions.watch.state.search;

import org.opensearch.action.ActionType;

public class SearchWatchStateAction extends ActionType<SearchWatchStateResponse> {

    public static final SearchWatchStateAction INSTANCE = new SearchWatchStateAction();
    public static final String NAME = "cluster:admin:searchguard:tenant:signals:watch:state/search";

    protected SearchWatchStateAction() {
        super(NAME, in -> {
            SearchWatchStateResponse response = new SearchWatchStateResponse(in);
            return response;
        });
    }
}
