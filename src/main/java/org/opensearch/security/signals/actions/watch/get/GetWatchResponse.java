package org.opensearch.security.signals.actions.watch.get;

import java.io.IOException;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.action.get.GetResponse;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.index.mapper.SourceFieldMapper;

public class GetWatchResponse extends ActionResponse implements ToXContentObject {

    private String tenant;
    private String id;
    private boolean exists;
    private long version;
    private long seqNo;
    private long primaryTerm;
    private BytesReference source;

    public GetWatchResponse() {
    }

    public GetWatchResponse(String tenant, String id, boolean exists) {
        this(tenant, id, exists, -1, -1, -1, null);
    }

    public GetWatchResponse(String tenant, String id, boolean exists, long version, long seqNo, long primaryTerm, BytesReference source) {
        super();
        this.tenant = tenant;
        this.id = id;
        this.exists = exists;
        this.version = version;
        this.seqNo = seqNo;
        this.primaryTerm = primaryTerm;
        this.source = source;
    }

    public GetWatchResponse(String tenant, GetResponse getResponse) {
        this.tenant = tenant;
        this.id = getResponse.getId();
        this.exists = getResponse.isExists();
        this.version = getResponse.getVersion();
        this.seqNo = getResponse.getSeqNo();
        this.primaryTerm = getResponse.getPrimaryTerm();
        this.source = getResponse.getSourceAsBytesRef();
    }

    public GetWatchResponse(StreamInput in) throws IOException {
        super(in);
        this.tenant = in.readOptionalString();
        this.id = in.readString();
        this.exists = in.readBoolean();
        this.version = in.readLong();
        this.seqNo = in.readLong();
        this.primaryTerm = in.readLong();
        this.source = in.readOptionalBytesReference();

    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(tenant);
        out.writeString(id);
        out.writeBoolean(exists);
        out.writeLong(version);
        out.writeLong(seqNo);
        out.writeLong(primaryTerm);
        out.writeOptionalBytesReference(source);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("_id", id);
        builder.field("_tenant", tenant);
        builder.field("found", exists);

        if (exists) {
            builder.field("_version", version);
            builder.field("_seq_no", seqNo);
            builder.field("_primary_term", primaryTerm);

            XContentHelper.writeRawField(SourceFieldMapper.NAME, source, XContentType.JSON, builder, params);
        }

        builder.endObject();
        return builder;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public boolean isExists() {
        return exists;
    }

    public void setExists(boolean exists) {
        this.exists = exists;
    }

    public long getVersion() {
        return version;
    }

    public void setVersion(long version) {
        this.version = version;
    }

    public long getSeqNo() {
        return seqNo;
    }

    public void setSeqNo(long seqNo) {
        this.seqNo = seqNo;
    }

    public long getPrimaryTerm() {
        return primaryTerm;
    }

    public void setPrimaryTerm(long primaryTerm) {
        this.primaryTerm = primaryTerm;
    }

    public BytesReference getSource() {
        return source;
    }

    public void setSource(BytesReference source) {
        this.source = source;
    }

    public String getTenant() {
        return tenant;
    }

    public void setTenant(String tenant) {
        this.tenant = tenant;
    }
}
