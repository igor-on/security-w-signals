
package org.opensearch.security.signals.actions.watch.state.get;

import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.rest.RestUtils.*;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.signals.Signals;
import org.opensearch.security.signals.SignalsTenant;
import org.opensearch.security.signals.SignalsUnavailableException;
import org.opensearch.security.signals.watch.state.WatchState;

public class TransportGetWatchStateAction extends HandledTransportAction<GetWatchStateRequest, GetWatchStateResponse> {

    private final static Logger log = LogManager.getLogger(TransportGetWatchStateAction.class);

    private final Signals signals;
    private final ThreadPool threadPool;

    @Inject
    public TransportGetWatchStateAction(Signals signals, TransportService transportService, ThreadPool threadPool, ActionFilters actionFilters,
            Client client) {
        super(GetWatchStateAction.NAME, transportService, actionFilters, GetWatchStateRequest::new);

        this.signals = signals;
        this.threadPool = threadPool;
    }

    @Override
    protected void doExecute(Task task, GetWatchStateRequest request, ActionListener<GetWatchStateResponse> listener) {

        try {
            ThreadContext threadContext = threadPool.getThreadContext();

            // TODO: IGOR_ON CHANGE
//            User user = threadContext.getTransient(ConfigConstants.SG_USER);
            User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

            if (user == null) {
                throw new RuntimeException("Request did not contain user");
            }

            SignalsTenant signalsTenant = signals.getTenant(user);

            threadPool.generic().submit(() -> {
                Map<String, WatchState> watchStates = signalsTenant.getWatchStateReader().get(request.getWatchIds());

                listener.onResponse(new GetWatchStateResponse(RestStatus.OK, toBytesReferenceMap(watchStates)));
            });
        } catch (SignalsUnavailableException e) {
            listener.onFailure(e.toElasticsearchException());         
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    private Map<String, BytesReference> toBytesReferenceMap(Map<String, WatchState> map) {
        Map<String, BytesReference> result = new HashMap<>(map.size());

        for (Map.Entry<String, WatchState> entry : map.entrySet()) {
            try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
                builder.value(entry.getValue());
                result.put(entry.getKey(), BytesReference.bytes(builder));
            } catch (Exception e) {
                log.error("Error while writing " + entry.getKey(), e);
            }
        }

        return result;
    }

}
