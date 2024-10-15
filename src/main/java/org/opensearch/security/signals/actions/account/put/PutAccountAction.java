package org.opensearch.security.signals.actions.account.put;

import org.opensearch.action.ActionType;

public class PutAccountAction extends ActionType<PutAccountResponse> {

    public static final PutAccountAction INSTANCE = new PutAccountAction();
    public static final String NAME = "cluster:admin:searchguard:signals:account/put";

    protected PutAccountAction() {
        super(NAME, in -> {
            PutAccountResponse response = new PutAccountResponse(in);
            return response;
        });
    }
}
