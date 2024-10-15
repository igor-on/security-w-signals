package org.opensearch.security.signals.actions.watch.get;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

public class GetWatchRequest extends ActionRequest {

    private String watchId;

    public GetWatchRequest() {
        super();
    }

    public GetWatchRequest(String watchId) {
        super();
        this.watchId = watchId;
    }

    public GetWatchRequest(StreamInput in) throws IOException {
        super(in);
        this.watchId = in.readString();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(watchId);
    }

    @Override
    public ActionRequestValidationException validate() {
        if (watchId == null || watchId.length() == 0) {
            return new ActionRequestValidationException();
        }
        return null;
    }

    public String getWatchId() {
        return watchId;
    }

    public void setWatchId(String watchId) {
        this.watchId = watchId;
    }

}
