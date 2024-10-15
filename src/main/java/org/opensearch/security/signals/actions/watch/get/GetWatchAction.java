package org.opensearch.security.signals.actions.watch.get;

import org.opensearch.action.ActionType;

public class GetWatchAction extends ActionType<GetWatchResponse> {

    public static final GetWatchAction INSTANCE = new GetWatchAction();
    public static final String NAME = "cluster:admin:searchguard:tenant:signals:watch/get";

    protected GetWatchAction() {
        super(NAME, in -> {
            GetWatchResponse response = new GetWatchResponse(in);
            return response;
        });
    }
}
