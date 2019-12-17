package io.xapix.capbac.resolvers;

import io.xapix.capbac.CapBAC;
import io.xapix.capbac.CapBACResolver;

import java.net.URL;
import java.util.Map;

public class StaticMapResolver implements CapBACResolver {
    private Map<URL, byte[]> map;

    public StaticMapResolver(Map<URL, byte[]> map) {
        this.map = map;
    }

    @Override
    public byte[] resolve(URL id) throws CapBAC.BadID {
        if (!map.containsKey(id)) {
            throw new CapBAC.BadID();
        }
        return map.get(id);
    }
}
