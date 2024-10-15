package org.opensearch.security.signals.watch.common;

import java.net.URI;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.support.WildcardMatcherSG;

public class HttpEndpointWhitelist {
    private final static Logger log = LogManager.getLogger(HttpEndpointWhitelist.class);

    private final List<String> whitelist;

    public HttpEndpointWhitelist(List<String> whitelist) {
        this.whitelist = whitelist;
    }

    public void check(URI uri) throws NotWhitelistedException {
        String uriAsString = uri.toString();

        if (log.isDebugEnabled()) {
            log.debug("Checking " + uri + " against " + whitelist);
        }

        for (String entry : whitelist) {
            // TODO: IGOR_ON CHANGE (WildcardMatcher to WildcardMatcherSG)
            if (WildcardMatcherSG.match(entry, uriAsString)) {
                return;
            }
        }

        throw new NotWhitelistedException(uri);
    }

    public static class NotWhitelistedException extends Exception {

        private static final long serialVersionUID = 5274286136737656655L;

        public NotWhitelistedException(URI uri) {
            super("The URI is not whitelisted: " + uri);
        }
    }
}
