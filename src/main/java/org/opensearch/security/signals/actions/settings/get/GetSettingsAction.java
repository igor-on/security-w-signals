package org.opensearch.security.signals.actions.settings.get;

import org.opensearch.action.ActionType;

public class GetSettingsAction extends ActionType<GetSettingsResponse> {

    public static final GetSettingsAction INSTANCE = new GetSettingsAction();
    public static final String NAME = "cluster:admin:searchguard:signals:settings/get";

    protected GetSettingsAction() {
        super(NAME, in -> {
            GetSettingsResponse response = new GetSettingsResponse(in);
            return response;
        });
    }
}
