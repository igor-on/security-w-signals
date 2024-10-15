package org.opensearch.security.signals.actions.account.search;

import org.opensearch.action.ActionType;

public class SearchAccountAction extends ActionType<SearchAccountResponse> {

    public static final SearchAccountAction INSTANCE = new SearchAccountAction();
    public static final String NAME = "cluster:admin:searchguard:signals:account/search";

    protected SearchAccountAction() {
        super(NAME, in -> {
            SearchAccountResponse response = new SearchAccountResponse(in);
            return response;
        });
    }
}
