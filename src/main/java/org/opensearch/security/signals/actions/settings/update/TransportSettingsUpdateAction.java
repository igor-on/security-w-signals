package org.opensearch.security.signals.actions.settings.update;

import java.io.IOException;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.nodes.BaseNodeRequest;
import org.opensearch.action.support.nodes.BaseNodeResponse;
import org.opensearch.action.support.nodes.TransportNodesAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.common.settings.Settings;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import org.opensearch.security.signals.Signals;

public class TransportSettingsUpdateAction extends
        TransportNodesAction<SettingsUpdateRequest, SettingsUpdateResponse, TransportSettingsUpdateAction.NodeRequest, TransportSettingsUpdateAction.NodeResponse> {

    private final static Logger log = LogManager.getLogger(TransportSettingsUpdateAction.class);

    private final Signals signals;
    private final Client client;

    @Inject
    public TransportSettingsUpdateAction(Signals signals, final Settings settings, final ThreadPool threadPool, final ClusterService clusterService,
            final TransportService transportService, final ActionFilters actionFilters, final Client client) {
        super(SettingsUpdateAction.NAME, threadPool, clusterService, transportService, actionFilters, SettingsUpdateRequest::new,
                TransportSettingsUpdateAction.NodeRequest::new, ThreadPool.Names.MANAGEMENT, TransportSettingsUpdateAction.NodeResponse.class);

        this.signals = signals;
        this.client = client;

    }

    @Override
    protected NodeResponse newNodeResponse(StreamInput in) throws IOException {
        return new NodeResponse(in);
    }

    @Override
    protected SettingsUpdateResponse newResponse(SettingsUpdateRequest request, List<NodeResponse> responses, List<FailedNodeException> failures) {
        return new SettingsUpdateResponse(this.clusterService.getClusterName(), responses, failures);

    }

    @Override
    protected NodeResponse nodeOperation(final NodeRequest request) {
        DiscoveryNode localNode = clusterService.localNode();

        try {
            signals.getSignalsSettings().refresh(client);

            return new NodeResponse(localNode, NodeResponse.Status.SUCCESS, "");
        } catch (Exception e) {
            log.error("Error while updating settings", e);
            return new NodeResponse(localNode, NodeResponse.Status.EXCEPTION, e.toString());
        }
    }

    public static class NodeRequest extends BaseNodeRequest {

        SettingsUpdateRequest request;

        public NodeRequest(StreamInput in) throws IOException {
            super(in);
            request = new SettingsUpdateRequest(in);
        }

        public NodeRequest(final SettingsUpdateRequest request) {
            this.request = request;
        }

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            super.writeTo(out);
            request.writeTo(out);
        }
    }

    public static class NodeResponse extends BaseNodeResponse {

        private Status status;
        private String message;

        public NodeResponse(StreamInput in) throws IOException {
            super(in);
            status = in.readEnum(Status.class);
            message = in.readOptionalString();
        }

        public NodeResponse(final DiscoveryNode node, Status status, String message) {
            super(node);
            this.status = status;
            this.message = message;
        }

        public String getMessage() {
            return message;
        }

        public Status getStatus() {
            return status;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeEnum(status);
            out.writeOptionalString(message);
        }

        @Override
        public String toString() {
            return "NodeResponse [status=" + status + ", message=" + message + "]";
        }

        
        public static NodeResponse readNodeResponse(StreamInput in) throws IOException {
            NodeResponse result = new NodeResponse(in);
            return result;
        }
        
        public static enum Status {
            SUCCESS, EXCEPTION
        }
    }

    @Override
    protected NodeRequest newNodeRequest(SettingsUpdateRequest request) {
        return new NodeRequest(request);
    }

}
