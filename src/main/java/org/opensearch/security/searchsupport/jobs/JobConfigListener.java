package org.opensearch.security.searchsupport.jobs;

import org.opensearch.security.searchsupport.jobs.config.JobConfig;

import java.util.Map;
import java.util.Set;

public interface JobConfigListener<JobType extends JobConfig> {

    void onInit(Set<JobType> jobs);

    void beforeChange(Set<JobType> newJobs);
    
    void afterChange(Set<JobType> newJobs, Map<JobType, JobType> updatedJobs, Set<JobType> deletedJobs);
}
