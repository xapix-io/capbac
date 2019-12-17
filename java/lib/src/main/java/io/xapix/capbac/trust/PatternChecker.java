package io.xapix.capbac.trust;

import io.xapix.capbac.CapBACTrustChecker;

import java.net.URL;
import java.util.regex.Pattern;

public class PatternChecker implements CapBACTrustChecker {
    private Pattern pattern;

    public PatternChecker(Pattern pattern) {
        this.pattern = pattern;
    }

    @Override
    public boolean check(URL id) {
        return pattern.matcher(id.toString()).matches();
    }
}
