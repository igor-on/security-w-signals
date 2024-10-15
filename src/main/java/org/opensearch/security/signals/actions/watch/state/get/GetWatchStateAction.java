
package org.opensearch.security.signals.actions.watch.state.get;

import org.opensearch.action.ActionType;

public class GetWatchStateAction extends ActionType<GetWatchStateResponse> {
    public static final GetWatchStateAction INSTANCE = new GetWatchStateAction();
    public static final String NAME = "cluster:admin:searchguard:tenant:signals:watch:state/get";

    protected GetWatchStateAction() {
        super(NAME, in -> {
            GetWatchStateResponse response = new GetWatchStateResponse(in);
            return response;
        });
    }
}
