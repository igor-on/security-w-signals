package org.opensearch.security.signals.actions.watch.get;

import org.opensearch.core.action.ActionListener;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.core.common.Strings;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.signals.NoSuchTenantException;
import org.opensearch.security.signals.Signals;
import org.opensearch.security.signals.SignalsTenant;
import org.opensearch.security.signals.SignalsUnavailableException;
import org.opensearch.security.signals.watch.Watch;

public class TransportGetWatchAction extends HandledTransportAction<GetWatchRequest, GetWatchResponse> {

    private final Signals signals;
    private final Client client;
    private final ThreadPool threadPool;

    @Inject
    public TransportGetWatchAction(Signals signals, TransportService transportService, ThreadPool threadPool, ActionFilters actionFilters,
            Client client) {
        super(GetWatchAction.NAME, transportService, actionFilters, GetWatchRequest::new);

        this.signals = signals;
        this.client = client;
        this.threadPool = threadPool;
    }

    @Override
    protected final void doExecute(Task task, GetWatchRequest request, ActionListener<GetWatchResponse> listener) {

        try {
            ThreadContext threadContext = threadPool.getThreadContext();

            // TODO: IGOR_ON CHANGE
//            User user = threadContext.getTransient(ConfigConstants.SG_USER);
//            Object remoteAddress = threadContext.getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
//            Object origin = threadContext.getTransient(ConfigConstants.SG_ORIGIN);
            User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            Object remoteAddress = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
            Object origin = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN);
            SignalsTenant signalsTenant = signals.getTenant(user);

            try (StoredContext ctx = threadPool.getThreadContext().stashContext()) {

//                threadContext.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true");
//                threadContext.putTransient(ConfigConstants.SG_USER, user);
//                threadContext.putTransient(ConfigConstants.SG_REMOTE_ADDRESS, remoteAddress);
//                threadContext.putTransient(ConfigConstants.SG_ORIGIN, origin);
                threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, remoteAddress);
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, origin);

                // TODO: IGOR_ON CHANGE
//                client.prepareGet(signalsTenant.getConfigIndexName(), null, signalsTenant.getWatchIdForConfigIndex(request.getWatchId()))
                client.prepareGet(signalsTenant.getConfigIndexName(), signalsTenant.getWatchIdForConfigIndex(request.getWatchId()))
                        .setFetchSource(Strings.EMPTY_ARRAY, Watch.HiddenAttributes.asArray()).execute(new ActionListener<GetResponse>() {

                            @Override
                            public void onResponse(GetResponse response) {
                                listener.onResponse(new GetWatchResponse(signalsTenant.getName(), response));
                            }

                            @Override
                            public void onFailure(Exception e) {
                                listener.onFailure(e);
                            }

                        });
            }
        } catch (NoSuchTenantException e) {
            listener.onResponse(new GetWatchResponse(e.getTenant(), request.getWatchId(), false));
        } catch (SignalsUnavailableException e) {
            listener.onFailure(e.toElasticsearchException());
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

}