
package org.opensearch.security.signals.actions.watch.ack;

import java.io.IOException;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.nodes.BaseNodeRequest;
import org.opensearch.action.support.nodes.BaseNodeResponse;
import org.opensearch.action.support.nodes.TransportNodesAction;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.signals.NoSuchWatchOnThisNodeException;
import org.opensearch.security.signals.Signals;
import org.opensearch.security.signals.SignalsTenant;

public class TransportAckWatchAction
        extends TransportNodesAction<AckWatchRequest, AckWatchResponse, TransportAckWatchAction.NodeRequest, TransportAckWatchAction.NodeResponse> {

    private final static Logger log = LogManager.getLogger(TransportAckWatchAction.class);

    private final Signals signals;
    private final ThreadPool threadPool;

    @Inject
    public TransportAckWatchAction(final Settings settings, final ThreadPool threadPool, final ClusterService clusterService,
            final TransportService transportService, final ActionFilters actionFilters, final Signals signals) {
        super(AckWatchAction.NAME, threadPool, clusterService, transportService, actionFilters, AckWatchRequest::new,
                TransportAckWatchAction.NodeRequest::new, ThreadPool.Names.MANAGEMENT, TransportAckWatchAction.NodeResponse.class);

        this.signals = signals;
        this.threadPool = threadPool;
    }

    @Override
    protected AckWatchResponse newResponse(AckWatchRequest request, List<NodeResponse> responses, List<FailedNodeException> failures) {
        return new AckWatchResponse(this.clusterService.getClusterName(), responses, failures);

    }

    @Override
    protected NodeResponse nodeOperation(final NodeRequest request) {

        try {
            DiscoveryNode localNode = clusterService.localNode();
            ThreadContext threadContext = threadPool.getThreadContext();

            // TODO: IGOR_ON CHANGE
//            User user = threadContext.getTransient(ConfigConstants.SG_USER);
            User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

            if (user == null) {
                return new NodeResponse(localNode, AckWatchResponse.Status.UNAUTHORIZED, "Request did not contain user");
            }

            SignalsTenant signalsTenant = signals.getTenant(user);

            if (signalsTenant == null) {
                return new NodeResponse(localNode, AckWatchResponse.Status.NO_SUCH_TENANT, "No such tenant: " + user.getRequestedTenant());
            }

            if (request.request.getWatchId() == null) {
                throw new IllegalArgumentException("request.watchId is null");
            }

            if (!signalsTenant.runsWatchLocally(request.request.getWatchId())) {
                return new NodeResponse(localNode, AckWatchResponse.Status.NO_SUCH_WATCH, "This node does not run " + request.request.getWatchId());
            }

            if (request.request.getActionId() != null) {
                try {
                    if (request.request.isAck()) {
                        signalsTenant.ack(request.request.getWatchId(), request.request.getActionId(), user);
                        return new NodeResponse(localNode, AckWatchResponse.Status.SUCCESS, "Acknowledged");
                    } else {
                        signalsTenant.unack(request.request.getWatchId(), request.request.getActionId(), user);
                        return new NodeResponse(localNode, AckWatchResponse.Status.SUCCESS, "Un-acknowledged");
                    }
                } catch (IllegalStateException e) {
                    return new NodeResponse(localNode, AckWatchResponse.Status.ILLEGAL_STATE, e.getMessage());
                }
            } else {
                if (request.request.isAck()) {
                    List<String> ackedActions = signalsTenant.ack(request.request.getWatchId(), user);

                    if (ackedActions.size() == 0) {
                        return new NodeResponse(localNode, AckWatchResponse.Status.ILLEGAL_STATE, "No actions are in an acknowlegable state");
                    } else {
                        return new NodeResponse(localNode, AckWatchResponse.Status.SUCCESS, "Acknowledged: " + ackedActions);
                    }
                } else {
                    List<String> unackedActions = signalsTenant.unack(request.request.getWatchId(), user);

                    if (unackedActions.size() == 0) {
                        return new NodeResponse(localNode, AckWatchResponse.Status.ILLEGAL_STATE, "No actions are in an un-acknowlegable state");
                    } else {
                        return new NodeResponse(localNode, AckWatchResponse.Status.SUCCESS, "Un-acknowledged: " + unackedActions);
                    }
                }
            }
        } catch (NoSuchWatchOnThisNodeException e) {
            // Note: We checked before signalsTenant.runsWatchLocally: If we get this exception anyway, this can only mean one thing:
            return new NodeResponse(clusterService.localNode(), AckWatchResponse.Status.ILLEGAL_STATE, "The watch has not been initialized yet");
        } catch (Exception e) {
            log.error("Error while acknowledging " + request.request, e);
            return new NodeResponse(clusterService.localNode(), AckWatchResponse.Status.EXCEPTION, e.toString());
        }
    }

    public static class NodeRequest extends BaseNodeRequest {

        AckWatchRequest request;

        public NodeRequest() {
        }

        public NodeRequest(final AckWatchRequest request) {
            this.request = request;
        }

        public NodeRequest(final StreamInput in) throws IOException {
            super(in);
            request = new AckWatchRequest(in);
        }

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            super.writeTo(out);
            request.writeTo(out);
        }
    }

    public static class NodeResponse extends BaseNodeResponse {

        private AckWatchResponse.Status status;
        private String message;

        public NodeResponse(final DiscoveryNode node, AckWatchResponse.Status status, String message) {
            super(node);
            this.status = status;
            this.message = message;
        }

        public NodeResponse(StreamInput in) throws IOException {
            super(in);
            status = in.readEnum(AckWatchResponse.Status.class);
            message = in.readOptionalString();
        }

        public static TransportAckWatchAction.NodeResponse readNodeResponse(StreamInput in) throws IOException {
            TransportAckWatchAction.NodeResponse result = new TransportAckWatchAction.NodeResponse(in);
            return result;
        }

        public String getMessage() {
            return message;
        }

        public AckWatchResponse.Status getStatus() {
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

    }

    @Override
    protected NodeRequest newNodeRequest(AckWatchRequest request) {
        return new NodeRequest(request);
    }

    @Override
    protected NodeResponse newNodeResponse(StreamInput in) throws IOException {
        return new NodeResponse(in);
    }

}
