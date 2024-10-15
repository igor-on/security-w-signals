package org.opensearch.security.signals.watch.state;

import java.io.IOException;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.DocWriteRequest.OpType;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;

public class WatchStateIndexWriter implements WatchStateWriter<IndexResponse> {
    private static final Logger log = LogManager.getLogger(WatchStateIndexWriter.class);

    private final String indexName;
    private final String watchIdPrefix;
    private final Client client;

    public WatchStateIndexWriter(String watchIdPrefix, String indexName, Client client) {
        this.watchIdPrefix = watchIdPrefix;
        this.indexName = indexName;
        this.client = client;
    }

    public void put(String watchId, WatchState watchState) {

        try {
            put(watchId, watchState, new ActionListener<IndexResponse>() {

                @Override
                public void onResponse(IndexResponse response) {
                    if (log.isDebugEnabled()) {
                        log.debug("Updated " + watchId + " to:\n" + watchState + "\n" + Strings.toString(MediaTypeRegistry.JSON, response));
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Error while writing WatchState " + watchState, e);
                }
            });

        } catch (Exception e) {
            log.error("Error while writing WatchState " + watchState, e);
        }
    }

    public void put(String watchId, WatchState watchState, ActionListener<IndexResponse> actionListener) {
        IndexRequest indexRequest = createIndexRequest(watchId, watchState, RefreshPolicy.IMMEDIATE, null);

        client.index(indexRequest, actionListener);
    }

    public void putAll(Map<String, WatchState> idToStateMap) {
        BulkRequest bulkRequest = new BulkRequest();

        for (Map.Entry<String, WatchState> entry : idToStateMap.entrySet()) {
            try {
                bulkRequest.add(createIndexRequest(entry.getKey(), entry.getValue(), RefreshPolicy.NONE, null));
            } catch (Exception e) {
                log.error("Error while serializing " + entry);
            }
        }

        client.bulk(bulkRequest, new ActionListener<BulkResponse>() {

            @Override
            public void onResponse(BulkResponse response) {
                if (log.isDebugEnabled()) {
                    log.debug("Updated " + idToStateMap.keySet() + "\n" + Strings.toString(MediaTypeRegistry.JSON, response));
                }
            }

            @Override
            public void onFailure(Exception e) {
                log.error("Error while writing WatchState " + idToStateMap, e);
            }
        });
    }

    private IndexRequest createIndexRequest(String watchId, WatchState watchState, RefreshPolicy refreshPolicy, OpType opType) {
        try (XContentBuilder jsonBuilder = XContentFactory.jsonBuilder()) {
            IndexRequest indexRequest = new IndexRequest(indexName).id(watchIdPrefix + watchId);
            
            if (opType != null) {
                indexRequest.opType(opType);
            }
            
            watchState.toXContent(jsonBuilder, ToXContent.EMPTY_PARAMS);
            indexRequest.source(jsonBuilder);
            indexRequest.setRefreshPolicy(refreshPolicy);

            return indexRequest;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void putIfAbsent(String watchId, WatchState watchState) {

        try {
            put(watchId, watchState, new ActionListener<IndexResponse>() {

                @Override
                public void onResponse(IndexResponse response) {
                    if (log.isDebugEnabled()) {
                        log.debug("Updated " + watchId + " to:\n" + watchState + "\n" + Strings.toString(MediaTypeRegistry.JSON, response));
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Error while writing WatchState " + watchState, e);
                }
            });

        } catch (Exception e) {
            log.error("Error while writing WatchState " + watchState, e);
        }        
    }
    
    public void putIfAbsent(String watchId, WatchState watchState, ActionListener<IndexResponse> actionListener) {
        IndexRequest indexRequest = createIndexRequest(watchId, watchState, RefreshPolicy.IMMEDIATE, OpType.CREATE);

        client.index(indexRequest, actionListener);
    }
}
