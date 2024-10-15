package org.opensearch.security.signals.actions.tenant.start_stop;

import org.opensearch.action.ActionType;

public class StartStopTenantAction extends ActionType<StartStopTenantResponse> {

    public static final StartStopTenantAction INSTANCE = new StartStopTenantAction();
    public static final String NAME = "cluster:admin:searchguard:tenant:signals:tenant/start_stop";

    protected StartStopTenantAction() {
        super(NAME, in -> {
            StartStopTenantResponse response = new StartStopTenantResponse(in);
            return response;
        });
    }

}
