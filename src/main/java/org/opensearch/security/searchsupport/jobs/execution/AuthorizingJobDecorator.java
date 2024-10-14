package org.opensearch.security.searchsupport.jobs.execution;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.spi.JobFactory;
import org.quartz.spi.TriggerFiredBundle;

import org.opensearch.security.internalauthtoken.InternalAuthTokenProvider;
import org.opensearch.security.searchsupport.jobs.config.JobConfig;
import org.opensearch.security.searchsupport.jobs.config.JobDetailWithBaseConfig;

public class AuthorizingJobDecorator implements Job {

    private final Job delegate;
    private final String authToken;
    private final ThreadContext threadContext;
    private final String authTokenAudience;

    AuthorizingJobDecorator(Job delegate, String authToken, String authTokenAudience, ThreadContext threadContext) {
        this.delegate = delegate;
        this.authToken = authToken;
        this.threadContext = threadContext;
        this.authTokenAudience = authTokenAudience;
    }

    @Override
    public void execute(JobExecutionContext context) throws JobExecutionException {
        try (StoredContext ctx = threadContext.stashContext()) {
            threadContext.putHeader(InternalAuthTokenProvider.TOKEN_HEADER, authToken);
            threadContext.putHeader(InternalAuthTokenProvider.AUDIENCE_HEADER, authTokenAudience);

            delegate.execute(context);
        }
    }

    public String toString() {
        return this.delegate.toString();
    }

    public static class DecoratingJobFactory implements JobFactory {

        private final ThreadContext threadContext;
        private final JobFactory delegate;

        public DecoratingJobFactory(ThreadContext threadContext, JobFactory delegate) {
            this.threadContext = threadContext;
            this.delegate = delegate;
        }

        @Override
        public Job newJob(TriggerFiredBundle bundle, Scheduler scheduler) throws SchedulerException {
            Job job = delegate.newJob(bundle, scheduler);
            JobConfig jobConfig = getConfig(bundle);
            String authToken = jobConfig.getAuthToken();
            String authTokenAudience = jobConfig.getSecureAuthTokenAudience();

            if (authToken != null && authTokenAudience != null) {
                return new AuthorizingJobDecorator(job, authToken, authTokenAudience, threadContext);
            } else {
                // TODO check if auth is ok
                return job;
            }
        }

        private JobConfig getConfig(TriggerFiredBundle bundle) {
            return ((JobDetailWithBaseConfig) bundle.getJobDetail()).getBaseConfig(JobConfig.class);
        }

    };

}
