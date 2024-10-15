package org.opensearch.security.signals.actions.tenant.start_stop;

import java.io.IOException;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

public class StartStopTenantResponse extends ActionResponse {

    public StartStopTenantResponse() {
    }

    public StartStopTenantResponse(StreamInput in) throws IOException {
        super(in);

    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {

    }

}
