package org.opensearch.security.signals.actions.settings.put;

import org.opensearch.action.ActionType;

public class PutSettingsAction extends ActionType<PutSettingsResponse> {

    public static final PutSettingsAction INSTANCE = new PutSettingsAction();
    public static final String NAME = "cluster:admin:searchguard:signals:settings/put";

    protected PutSettingsAction() {
        super(NAME, in -> {
            PutSettingsResponse response = new PutSettingsResponse(in);
            return response;
        });
    }
}
