package org.opensearch.security.signals.actions.account.get;

import org.opensearch.action.ActionType;

public class GetAccountAction extends ActionType<GetAccountResponse> {

    public static final GetAccountAction INSTANCE = new GetAccountAction();
    public static final String NAME = "cluster:admin:searchguard:signals:account/get";

    protected GetAccountAction() {
        super(NAME, in -> {
            GetAccountResponse response = new GetAccountResponse(in);
            return response;
        });
    }
}
