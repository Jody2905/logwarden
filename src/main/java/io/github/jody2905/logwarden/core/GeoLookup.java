package io.github.jody2905.logwarden.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Turns an IPv4 address into a rough location, for the impossible-travel rule.
 *
 * <p>Ships with a small table over the address ranges reserved for documentation (192.0.2.0/24,
 * 198.51.100.0/24, 203.0.113.0/24), which the attack simulator uses, plus the private office network.
 * Load a CSV of your own ranges with {@link #load(Reader)}: {@code cidr,city,country,lat,lon}.
 */
public final class GeoLookup {

    public record Place(String city, String country, double lat, double lon) {
        public String label() {
            return city + ", " + country;
        }
    }

    private record Range(long start, long end, Place place) { }

    private final List<Range> ranges = new ArrayList<>();

    public static GeoLookup withSampleRanges() {
        GeoLookup g = new GeoLookup();
        g.add("10.0.0.0/8", new Place("Kingstown (office)", "VC", 13.1600, -61.2248));
        g.add("192.168.0.0/16", new Place("Kingstown (office)", "VC", 13.1600, -61.2248));
        g.add("192.0.2.0/26", new Place("Kingstown", "VC", 13.1587, -61.2248));
        g.add("192.0.2.64/26", new Place("Bridgetown", "BB", 13.0975, -59.6167));
        g.add("192.0.2.128/26", new Place("Miami", "US", 25.7617, -80.1918));
        g.add("192.0.2.192/26", new Place("New York", "US", 40.7128, -74.0060));
        g.add("198.51.100.0/26", new Place("London", "GB", 51.5072, -0.1276));
        g.add("198.51.100.64/26", new Place("Lagos", "NG", 6.5244, 3.3792));
        g.add("198.51.100.128/26", new Place("São Paulo", "BR", -23.5558, -46.6396));
        g.add("198.51.100.192/26", new Place("Frankfurt", "DE", 50.1109, 8.6821));
        g.add("203.0.113.0/26", new Place("Moscow", "RU", 55.7558, 37.6173));
        g.add("203.0.113.64/26", new Place("Beijing", "CN", 39.9042, 116.4074));
        g.add("203.0.113.128/26", new Place("Singapore", "SG", 1.3521, 103.8198));
        g.add("203.0.113.192/26", new Place("Amsterdam", "NL", 52.3676, 4.9041));
        return g;
    }

    public void add(String cidr, Place place) {
        String[] parts = cidr.split("/");
        long base = toLong(parts[0]);
        int bits = Integer.parseInt(parts[1]);
        long size = 1L << (32 - bits);
        long start = base & ~(size - 1) & 0xFFFFFFFFL;
        ranges.add(new Range(start, start + size - 1, place));
    }

    /** CSV lines: cidr,city,country,lat,lon (a header line and # comments are skipped). */
    public GeoLookup load(Reader csv) throws IOException {
        try (BufferedReader r = new BufferedReader(csv)) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#") || line.startsWith("cidr")) continue;
                String[] f = line.split(",");
                add(f[0].strip(), new Place(f[1].strip(), f[2].strip(), Double.parseDouble(f[3]), Double.parseDouble(f[4])));
            }
        }
        return this;
    }

    public Optional<Place> find(String ip) {
        if (ip == null || !ip.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return Optional.empty();
        long v = toLong(ip);
        // Most specific match wins
        Range best = null;
        for (Range r : ranges) {
            if (v >= r.start && v <= r.end && (best == null || r.end - r.start < best.end - best.start)) best = r;
        }
        return Optional.ofNullable(best).map(Range::place);
    }

    public static boolean isPrivate(String ip) {
        if (ip == null) return false;
        return ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.")
                || ip.matches("172\\.(1[6-9]|2\\d|3[01])\\..*");
    }

    /** Great-circle distance in km. */
    public static double km(Place a, Place b) {
        double r = Math.PI / 180, dLat = (b.lat() - a.lat()) * r, dLon = (b.lon() - a.lon()) * r;
        double h = Math.sin(dLat / 2) * Math.sin(dLat / 2)
                + Math.cos(a.lat() * r) * Math.cos(b.lat() * r) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
        return 2 * 6371 * Math.asin(Math.sqrt(h));
    }

    private static long toLong(String ip) {
        long v = 0;
        for (String p : ip.split("\\.")) v = (v << 8) | Integer.parseInt(p);
        return v;
    }
}
