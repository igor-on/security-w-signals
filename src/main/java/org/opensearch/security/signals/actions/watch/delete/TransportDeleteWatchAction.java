package org.opensearch.security.signals.actions.watch.delete;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.DocWriteResponse.Result;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.core.common.Strings;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.searchsupport.jobs.actions.SchedulerConfigUpdateAction;
import org.opensearch.security.signals.NoSuchTenantException;
import org.opensearch.security.signals.Signals;
import org.opensearch.security.signals.SignalsTenant;
import org.opensearch.security.signals.SignalsUnavailableException;

public class TransportDeleteWatchAction extends HandledTransportAction<DeleteWatchRequest, DeleteWatchResponse> {
    private static final Logger log = LogManager.getLogger(TransportDeleteWatchAction.class);

    private final Signals signals;
    private final Client client;
    private final ThreadPool threadPool;

    @Inject
    public TransportDeleteWatchAction(Signals signals, TransportService transportService, ThreadPool threadPool, ActionFilters actionFilters,
            Client client) {
        super(DeleteWatchAction.NAME, transportService, actionFilters, DeleteWatchRequest::new);

        this.signals = signals;
        this.client = client;
        this.threadPool = threadPool;
    }

    @Override
    protected final void doExecute(Task task, DeleteWatchRequest request, ActionListener<DeleteWatchResponse> listener) {
        try {
            ThreadContext threadContext = threadPool.getThreadContext();

            // TODO: IGOR_ON CHANGE
//            User user = threadContext.getTransient(ConfigConstants.SG_USER);
            User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

            if (user == null) {
                listener.onResponse(
                        new DeleteWatchResponse(request.getWatchId(), -1, Result.NOOP, RestStatus.UNAUTHORIZED, "Request did not contain user"));
                return;
            }

            SignalsTenant signalsTenant = signals.getTenant(user);
//            Object originalRemoteAddress = threadContext.getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
//            Object originalOrigin = threadContext.getTransient(ConfigConstants.SG_ORIGIN);
            Object originalRemoteAddress = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
            Object originalOrigin = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN);

            try (StoredContext ctx = threadContext.stashContext()) {

//                threadContext.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true");
//                threadContext.putTransient(ConfigConstants.SG_USER, user);
//                threadContext.putTransient(ConfigConstants.SG_REMOTE_ADDRESS, originalRemoteAddress);
//                threadContext.putTransient(ConfigConstants.SG_ORIGIN, originalOrigin);
                threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, originalRemoteAddress);
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, originalOrigin);

                String idInIndex = signalsTenant.getWatchIdForConfigIndex(request.getWatchId());

//                client.prepareDelete(signalsTenant.getConfigIndexName(), null, idInIndex).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                client.prepareDelete(signalsTenant.getConfigIndexName(), idInIndex).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                        .execute(new ActionListener<DeleteResponse>() {
                            @Override
                            public void onResponse(DeleteResponse response) {

                                if (response.getResult() == Result.DELETED) {
                                    SchedulerConfigUpdateAction.send(client, signalsTenant.getScopedName());
                                }

                                try (StoredContext ctx = threadContext.stashContext()) {

//                                    threadContext.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true");
//                                    threadContext.putTransient(ConfigConstants.SG_USER, user);
//                                    threadContext.putTransient(ConfigConstants.SG_REMOTE_ADDRESS, originalRemoteAddress);
//                                    threadContext.putTransient(ConfigConstants.SG_ORIGIN, originalOrigin);
                                    threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
                                    threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
                                    threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, originalRemoteAddress);
                                    threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, originalOrigin);

//                                    client.prepareDelete(signalsTenant.getSettings().getStaticSettings().getIndexNames().getWatchesState(), null, idInIndex)
                                    client.prepareDelete(signalsTenant.getSettings().getStaticSettings().getIndexNames().getWatchesState(), idInIndex)
                                            .setRefreshPolicy(RefreshPolicy.IMMEDIATE).execute(new ActionListener<DeleteResponse>() {

                                                @Override
                                                public void onResponse(DeleteResponse response) {
                                                    if (log.isDebugEnabled()) {
                                                        log.debug("Result of deleting state " + idInIndex + "\n" + Strings.toString(MediaTypeRegistry.JSON, response));
                                                    }
                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    log.error("Error while deleting state " + idInIndex, e);
                                                }

                                            });
                                }
                                
                                listener.onResponse(new DeleteWatchResponse(request.getWatchId(), response.getVersion(), response.getResult(),
                                        response.status(), null));
                            }

                            @Override
                            public void onFailure(Exception e) {
                                listener.onFailure(e);
                            }
                        });
            }
        } catch (NoSuchTenantException e) {
            listener.onResponse(new DeleteWatchResponse(request.getWatchId(), -1, Result.NOT_FOUND, RestStatus.NOT_FOUND, e.getMessage()));
        } catch (SignalsUnavailableException e) {
            listener.onFailure(e.toElasticsearchException());
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

}