package org.opensearch.security.signals.actions.watch.delete;

import org.opensearch.action.ActionType;

public class DeleteWatchAction extends ActionType<DeleteWatchResponse> {

    public static final DeleteWatchAction INSTANCE = new DeleteWatchAction();
    public static final String NAME = "cluster:admin:searchguard:tenant:signals:watch/delete";

    protected DeleteWatchAction() {
        super(NAME, in -> {
            DeleteWatchResponse response = new DeleteWatchResponse(in);
            return response;
        });
    }
}
