package org.opensearch.security.signals.actions.watch.search;

import org.opensearch.core.action.ActionListener;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.signals.Signals;
import org.opensearch.security.signals.SignalsTenant;
import org.opensearch.security.signals.watch.Watch;

public class TransportSearchWatchAction extends HandledTransportAction<SearchWatchRequest, SearchWatchResponse> {

    private final Signals signals;
    private final Client client;
    private final ThreadPool threadPool;

    @Inject
    public TransportSearchWatchAction(Signals signals, TransportService transportService, ThreadPool threadPool, ActionFilters actionFilters,
            Client client) {
        super(SearchWatchAction.NAME, transportService, actionFilters, SearchWatchRequest::new);

        this.signals = signals;
        this.client = client;
        this.threadPool = threadPool;
    }

    @Override
    protected final void doExecute(Task task, SearchWatchRequest request, ActionListener<SearchWatchResponse> listener) {
        try {
            ThreadContext threadContext = threadPool.getThreadContext();

            // TODO: IGOR_ON CHANGE
//            User user = threadContext.getTransient(ConfigConstants.SG_USER);
            User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

            if (user == null) {
                throw new Exception("No user set");
            }

            SignalsTenant signalsTenant = signals.getTenant(user);

            if (signalsTenant == null) {
                throw new Exception("Unknown tenant: " + user.getRequestedTenant());
            }

//            Object remoteAddress = threadContext.getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
//            Object origin = threadContext.getTransient(ConfigConstants.SG_ORIGIN);
            Object remoteAddress = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
            Object origin = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN);

            try (StoredContext ctx = threadPool.getThreadContext().stashContext()) {

//                threadContext.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true");
//                threadContext.putTransient(ConfigConstants.SG_USER, user);
//                threadContext.putTransient(ConfigConstants.SG_REMOTE_ADDRESS, remoteAddress);
//                threadContext.putTransient(ConfigConstants.SG_ORIGIN, origin);
                threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, remoteAddress);
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, origin);

                SearchRequest searchRequest = new SearchRequest(signalsTenant.getConfigIndexName());

                if (request.getScroll() != null) {
                    searchRequest.scroll(request.getScroll());
                }

                SearchSourceBuilder searchSourceBuilder = request.getSearchSourceBuilder();

                if (searchSourceBuilder == null) {
                    searchSourceBuilder = new SearchSourceBuilder();
                    searchSourceBuilder.query(QueryBuilders.termQuery("_tenant", signalsTenant.getName()));
                } else {
                    QueryBuilder originalQuery = searchSourceBuilder.query();
                    BoolQueryBuilder newQuery = QueryBuilders.boolQuery().must(QueryBuilders.termQuery("_tenant", signalsTenant.getName()));

                    if (originalQuery != null) {
                        newQuery.must(originalQuery);
                    }

                    searchSourceBuilder.query(newQuery);
                }

                if (request.getFrom() != -1) {
                    searchSourceBuilder.from(request.getFrom());
                }

                if (request.getSize() != -1) {
                    searchSourceBuilder.size(request.getSize());
                }

                searchSourceBuilder.fetchSource(Watch.HiddenAttributes.FETCH_SOURCE_CONTEXT);

                searchRequest.source(searchSourceBuilder);

                client.execute(SearchAction.INSTANCE, searchRequest, new ActionListener<SearchResponse>() {

                    @Override
                    public void onResponse(SearchResponse response) {

                        listener.onResponse(new SearchWatchResponse(response));
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