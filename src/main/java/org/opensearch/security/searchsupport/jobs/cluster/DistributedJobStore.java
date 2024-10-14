package org.opensearch.security.searchsupport.jobs.cluster;

import org.opensearch.cluster.ClusterChangedEvent;
import org.quartz.spi.JobStore;

public interface DistributedJobStore extends JobStore {
    void clusterConfigChanged(ClusterChangedEvent event);

    boolean isInitialized();
}
