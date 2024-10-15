package org.opensearch.security.signals.actions.watch.activate_deactivate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.DocWriteResponse.Result;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.searchsupport.jobs.actions.SchedulerConfigUpdateAction;
import org.opensearch.security.signals.Signals;
import org.opensearch.security.signals.SignalsTenant;

public class TransportDeActivateWatchAction extends HandledTransportAction<DeActivateWatchRequest, DeActivateWatchResponse> {
    private static final Logger log = LogManager.getLogger(TransportDeActivateWatchAction.class);

    private final Signals signals;
    private final Client client;
    private final ThreadPool threadPool;

    @Inject
    public TransportDeActivateWatchAction(Signals signals, TransportService transportService, ThreadPool threadPool, ActionFilters actionFilters,
            Client client) {
        super(DeActivateWatchAction.NAME, transportService, actionFilters, DeActivateWatchRequest::new);

        this.signals = signals;
        this.client = client;
        this.threadPool = threadPool;
    }

    @Override
    protected final void doExecute(Task task, DeActivateWatchRequest request, ActionListener<DeActivateWatchResponse> listener) {
        try (XContentBuilder watchContentBuilder = XContentFactory.jsonBuilder()) {

            ThreadContext threadContext = threadPool.getThreadContext();

            User user = threadContext.getTransient(ConfigConstants.SG_USER);

            if (user == null) {
                listener.onResponse(
                        new DeActivateWatchResponse(request.getWatchId(), -1, Result.NOOP, RestStatus.UNAUTHORIZED, "Request did not contain user"));
                return;
            }

            SignalsTenant signalsTenant = signals.getTenant(user);

            if (signalsTenant == null) {
                listener.onResponse(new DeActivateWatchResponse(request.getWatchId(), -1, Result.NOT_FOUND, RestStatus.NOT_FOUND,
                        "No such tenant: " + user.getRequestedTenant()));
                return;
            }

            Object remoteAddress = threadContext.getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
            Object origin = threadContext.getTransient(ConfigConstants.SG_ORIGIN);

            try (StoredContext ctx = threadPool.getThreadContext().stashContext()) {

                threadContext.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true");
                threadContext.putTransient(ConfigConstants.SG_USER, user);
                threadContext.putTransient(ConfigConstants.SG_REMOTE_ADDRESS, remoteAddress);
                threadContext.putTransient(ConfigConstants.SG_ORIGIN, origin);

                UpdateRequest updateRequest = new UpdateRequest(signalsTenant.getConfigIndexName(),
                        signalsTenant.getWatchIdForConfigIndex(request.getWatchId()));
                updateRequest.doc("active", request.isActivate());
                updateRequest.setRefreshPolicy(RefreshPolicy.IMMEDIATE);

                client.update(updateRequest, new ActionListener<UpdateResponse>() {

                    @Override
                    public void onResponse(UpdateResponse response) {
                        if (log.isDebugEnabled()) {
                            log.debug("Got response " + response + " for " + updateRequest);
                        }

                        if (response.getResult() == UpdateResponse.Result.UPDATED) {
                            SchedulerConfigUpdateAction.send(client, signalsTenant.getScopedName());

                            listener.onResponse(new DeActivateWatchResponse(request.getWatchId(), response.getVersion(), response.getResult(),
                                    RestStatus.OK, null));
                        } else if (response.getResult() == UpdateResponse.Result.NOOP) {
                            // Nothing changed

                            listener.onResponse(new DeActivateWatchResponse(request.getWatchId(), response.getVersion(), response.getResult(),
                                    RestStatus.OK, null));
                        } else if (response.getResult() == UpdateResponse.Result.NOT_FOUND) {
                            listener.onResponse(new DeActivateWatchResponse(request.getWatchId(), response.getVersion(),
                                    UpdateResponse.Result.NOT_FOUND, RestStatus.NOT_FOUND, "No such watch: " + request.getWatchId()));
                        } else {
                            log.error("Unexpected result " + response + " in " + response + " for " + updateRequest);
                            listener.onResponse(new DeActivateWatchResponse(request.getWatchId(), response.getVersion(), response.getResult(),
                                    RestStatus.INTERNAL_SERVER_ERROR,
                                    "Unexpected result " + response.getResult() + " in " + response + " for " + updateRequest));

                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }

                });
            }
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

}