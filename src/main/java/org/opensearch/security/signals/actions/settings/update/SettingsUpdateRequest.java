package org.opensearch.security.signals.actions.settings.update;

import java.io.IOException;

import org.opensearch.action.support.nodes.BaseNodesRequest;
import org.opensearch.core.common.io.stream.StreamInput;

public class SettingsUpdateRequest extends BaseNodesRequest<SettingsUpdateRequest> {

    public SettingsUpdateRequest() {
        super((String[]) null);
    }

    public SettingsUpdateRequest(StreamInput in) throws IOException {
        super(in);
    }
}
