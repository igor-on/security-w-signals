package org.opensearch.security.signals.watch.result;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.core.common.Strings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;

import org.opensearch.security.internalauthtoken.InternalAuthTokenProvider;
import org.opensearch.security.signals.settings.SignalsSettings;

/**
 * TODO maybe integrate this with scheduler framework? We won't get logs right now if something
 * in the scheduler goes wrong
 *
 */
public class WatchLogIndexWriter implements WatchLogWriter {
    private static final Logger log = LogManager.getLogger(WatchLogIndexWriter.class);

    private final Client client;
    private final String tenant;
    private final SignalsSettings settings;
    private final ToXContent.Params toXparams;
    private final RefreshPolicy refreshPolicy;
    private final boolean syncIndexing;

    public WatchLogIndexWriter(Client client, String tenant, SignalsSettings settings, ToXContent.Params toXparams) {
        this.client = client;
        this.tenant = tenant;
        this.settings = settings;
        this.toXparams = toXparams;
        this.refreshPolicy = settings.getStaticSettings().getWatchLogRefreshPolicy();
        this.syncIndexing = settings.getStaticSettings().isWatchLogSyncIndexingEnabled();
    }

    @Override
    public void put(WatchLog watchLog) {
        String indexName = settings.getDynamicSettings().getWatchLogIndex();

        IndexRequest indexRequest = new IndexRequest(indexName);
        ThreadContext threadContext = client.threadPool().getThreadContext();

        try (XContentBuilder jsonBuilder = XContentFactory.jsonBuilder(); StoredContext storedContext = threadContext.stashContext()) {

            if (watchLog.getTenant() == null) {
                watchLog.setTenant(tenant);
            }

            if (log.isDebugEnabled()) {
                log.debug("Going to write WatchLog " + (refreshPolicy == RefreshPolicy.IMMEDIATE ? " (immediate) " : "") + watchLog);
            }

            // Elevate permissions
            threadContext.putHeader(InternalAuthTokenProvider.TOKEN_HEADER, null);
            threadContext.putHeader(InternalAuthTokenProvider.AUDIENCE_HEADER, null);

            watchLog.toXContent(jsonBuilder, toXparams);
            indexRequest.source(jsonBuilder);
            indexRequest.setRefreshPolicy(refreshPolicy);

            if (syncIndexing) {
                IndexResponse response = client.index(indexRequest).actionGet();
                
                if (log.isDebugEnabled()) {
                    log.debug("Completed sync writing WatchLog: " + watchLog + "\n" + Strings.toString(MediaTypeRegistry.JSON, response));
                }
            } else {
                client.index(indexRequest, new ActionListener<IndexResponse>() {

                    @Override
                    public void onResponse(IndexResponse response) {
                        if (log.isDebugEnabled()) {
                            log.debug("Completed writing WatchLog: " + watchLog + "\n" + Strings.toString(MediaTypeRegistry.JSON, response));
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Error while writing WatchLog " + watchLog, e);
                    }
                });
            }

        } catch (Exception e) {
            log.error("Error while writing WatchLog " + watchLog, e);
        }

    }

    public static WatchLogIndexWriter forTenant(Client client, String tenantName, SignalsSettings settings, ToXContent.Params toXparams) {
        return new WatchLogIndexWriter(client, tenantName, settings, toXparams);
    }
}
