package org.opensearch.security.searchsupport.jobs.actions;

import org.opensearch.action.ActionType;

public class CheckForExecutingTriggerAction extends ActionType<CheckForExecutingTriggerResponse> {

    public static final CheckForExecutingTriggerAction INSTANCE = new CheckForExecutingTriggerAction();
    public static final String NAME = "cluster:admin/searchsupport/scheduler/executing_triggers/check";

    protected CheckForExecutingTriggerAction() {
        super(NAME, in -> {
            CheckForExecutingTriggerResponse response = new CheckForExecutingTriggerResponse(in);
            return response;
        });
    }
}
