
package org.opensearch.security.signals.actions.watch.state.get;

import java.io.IOException;
import java.util.List;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

public class GetWatchStateRequest extends ActionRequest {

    private List<String> watchIds;

    public GetWatchStateRequest() {
        super();
    }

    public GetWatchStateRequest(List<String> watchIds) {
        super();
        this.watchIds = watchIds;
    }

    public GetWatchStateRequest(StreamInput in) throws IOException {
        super(in);
        this.watchIds = in.readStringList();

    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeStringCollection(watchIds);

    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public List<String> getWatchIds() {
        return watchIds;
    }

    public void setWatchIds(List<String> watchIds) {
        this.watchIds = watchIds;
    }

}
