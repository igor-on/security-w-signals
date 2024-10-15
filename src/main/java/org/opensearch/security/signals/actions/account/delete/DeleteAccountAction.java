package org.opensearch.security.signals.actions.account.delete;

import org.opensearch.action.ActionType;

public class DeleteAccountAction extends ActionType<DeleteAccountResponse> {

    public static final DeleteAccountAction INSTANCE = new DeleteAccountAction();
    public static final String NAME = "cluster:admin:searchguard:signals:account/delete";

    protected DeleteAccountAction() {
        super(NAME, in -> {
            DeleteAccountResponse response = new DeleteAccountResponse(in);
            return response;
        });
    }

}
