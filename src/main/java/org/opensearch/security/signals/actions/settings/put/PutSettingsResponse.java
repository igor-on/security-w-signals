package org.opensearch.security.signals.actions.settings.put;

import java.io.IOException;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.action.DocWriteResponse.Result;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.rest.RestStatus;

public class PutSettingsResponse extends ActionResponse implements ToXContentObject {

    private Result result;
    private RestStatus restStatus;
    private String message;
    private String detailJsonDocument;

    public PutSettingsResponse() {
    }

    public PutSettingsResponse(Result result, RestStatus restStatus, String message, String detailJsonDocument) {

        this.result = result;
        this.restStatus = restStatus;
        this.message = message;
        this.detailJsonDocument = detailJsonDocument;
    }

    public PutSettingsResponse(StreamInput in) throws IOException {
        super(in);

        result = in.readEnum(Result.class);
        restStatus = in.readEnum(RestStatus.class);
        message = in.readOptionalString();
        detailJsonDocument = in.readOptionalString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {

        out.writeEnum(this.result);
        out.writeEnum(restStatus);
        out.writeOptionalString(message);
        out.writeOptionalString(detailJsonDocument);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();

        builder.field("result", result.getLowercase());

        if (message != null) {
            builder.field("message", message);
        }

        builder.endObject();
        return builder;
    }

    public Result getResult() {
        return result;
    }

    public void setResult(Result result) {
        this.result = result;
    }

    public RestStatus getRestStatus() {
        return restStatus;
    }

    public void setRestStatus(RestStatus restStatus) {
        this.restStatus = restStatus;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getDetailJsonDocument() {
        return detailJsonDocument;
    }

    public void setDetailJsonDocument(String detailJsonDocument) {
        this.detailJsonDocument = detailJsonDocument;
    }

}
