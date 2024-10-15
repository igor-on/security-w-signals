package org.opensearch.security.signals.actions.account.config_update;

import java.io.IOException;

import org.opensearch.action.support.nodes.BaseNodesRequest;
import org.opensearch.core.common.io.stream.StreamInput;

public class DestinationConfigUpdateRequest extends BaseNodesRequest<DestinationConfigUpdateRequest> {

    public DestinationConfigUpdateRequest() {
        super((String[]) null);
    }

    public DestinationConfigUpdateRequest(StreamInput in) throws IOException {
        super(in);
    }
}
