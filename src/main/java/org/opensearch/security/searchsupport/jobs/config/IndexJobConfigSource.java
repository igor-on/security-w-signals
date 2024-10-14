package org.opensearch.security.searchsupport.jobs.config;

import java.util.Iterator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;

import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.searchsupport.jobs.cluster.JobDistributor;

public class IndexJobConfigSource<JobType extends JobConfig> implements Iterable<JobType> {
    private final static Logger log = LogManager.getLogger(IndexJobConfigSource.class);

    private final String indexName;
    private final Client client;
    private final JobConfigFactory<JobType> jobFactory;
    private final JobDistributor jobDistributor;
    private final QueryBuilder query;

    public IndexJobConfigSource(String indexName, Client client, JobConfigFactory<JobType> jobFactory, JobDistributor jobDistributor) {
        this(indexName, null, client, jobFactory, jobDistributor);
    }

    public IndexJobConfigSource(String indexName, QueryBuilder query, Client client, JobConfigFactory<JobType> jobFactory,
            JobDistributor jobDistributor) {
        this.indexName = indexName;
        this.client = client;
        this.jobFactory = jobFactory;
        this.jobDistributor = jobDistributor;
        this.query = query != null ? query : QueryBuilders.boolQuery().mustNot(QueryBuilders.termQuery("active", false));
    }

    @Override
    public Iterator<JobType> iterator() {
        return new IndexJobConfigIterator();
    }

    private class IndexJobConfigIterator implements Iterator<JobType> {
        private Iterator<SearchHit> searchHitIterator;
        private SearchRequest searchRequest;
        private SearchResponse searchResponse;
        private SearchHits searchHits;
        private JobType current;
        private boolean done = false;
        private int loaded = 0;
        private int filtered = 0;

        @Override
        public boolean hasNext() {
            lazyInit();

            return current != null;
        }

        @Override
        public JobType next() {
            lazyInit();

            JobType result = this.current;

            this.current = null;

            return result;
        }

        private void lazyInit() {
            if (this.done) {
                return;
            }

            if (this.searchRequest == null) {
                try {
                    this.searchRequest = new SearchRequest(indexName);
                    this.searchRequest.source(new SearchSourceBuilder().query(query).size(1000).version(true));
                    this.searchRequest.scroll(new TimeValue(10000));

                    if (log.isDebugEnabled()) {
                        log.debug("Executing " + this.searchRequest);
                    }

                    this.searchResponse = client.search(searchRequest).actionGet();
                    this.searchHits = this.searchResponse.getHits();
                    this.searchHitIterator = this.searchHits.iterator();
                } catch (IndexNotFoundException e) {
                    this.done = true;
                    return;
                }
            }

            while (this.current == null) {
                if (this.searchHits.getTotalHits().value == 0) {
                    break;
                }

                if (!this.searchHitIterator.hasNext()) {
                    this.searchResponse = client.prepareSearchScroll(this.searchResponse.getScrollId()).setScroll(new TimeValue(10000)).execute()
                            .actionGet();
                    this.searchHits = this.searchResponse.getHits();
                    this.searchHitIterator = this.searchHits.iterator();

                    if (!this.searchHitIterator.hasNext()) {
                        break;
                    }
                }

                SearchHit searchHit = this.searchHitIterator.next();
                try {
                    JobType job = jobFactory.createFromBytes(searchHit.getId(), searchHit.getSourceRef(), searchHit.getVersion());

                    if (jobDistributor == null || jobDistributor.isJobSelected(job)) {
                        this.current = job;
                        this.loaded++;
                    } else {
                        this.filtered++;
                    }

                } catch (ConfigValidationException e) {
                    log.error("Error while parsing job config " + indexName + "/" + searchHit.getId() + ":\n\n" + searchHit.getSourceAsString()
                            + "\n\n" + e.getValidationErrors(), e);
                } catch (Exception e) {
                    log.error("Error while parsing job config " + indexName + "/" + searchHit.getId() + ":\n\n" + searchHit.getSourceAsString(), e);
                }
            }

            if (this.current == null) {
                this.done = true;

                if (log.isDebugEnabled()) {
                    log.debug("Loaded jobs from " + indexName + ": " + loaded + "; filtered: " + filtered);
                }
            }

        }

    }

    @Override
    public String toString() {
        return "IndexJobConfigSource [indexName=" + indexName + ", jobFactory=" + jobFactory + ", jobDistributor=" + jobDistributor + "]";
    }

}
