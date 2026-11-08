package io.github.jody2905.logwarden.core.parse;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reads one flat JSON object (a Windows event exported as JSON lines) into a map of strings.
 * Nested objects and arrays are kept as their raw text. Keeps the detection core free of libraries.
 */
final class MiniJson {

    private final String s;
    private int i;

    private MiniJson(String s) {
        this.s = s;
    }

    static Map<String, String> object(String text) {
        MiniJson j = new MiniJson(text.strip());
        j.ws();
        j.expect('{');
        Map<String, String> out = new LinkedHashMap<>();
        j.ws();
        if (j.peek() == '}') return out;
        while (true) {
            j.ws();
            String key = j.string();
            j.ws();
            j.expect(':');
            j.ws();
            out.put(key, j.value());
            j.ws();
            char c = j.next();
            if (c == '}') return out;
            if (c != ',') throw new IllegalArgumentException("Expected , or } at " + j.i);
        }
    }

    private String value() {
        char c = peek();
        if (c == '"') return string();
        if (c == '{' || c == '[') return nested();
        int start = i;
        while (i < s.length() && ",}] \t\r\n".indexOf(s.charAt(i)) < 0) i++;
        String lit = s.substring(start, i);
        return lit.equals("null") ? null : lit;
    }

    private String nested() {
        int depth = 0, start = i;
        boolean inStr = false;
        for (; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (c == '\\') i++;
                else if (c == '"') inStr = false;
            } else if (c == '"') inStr = true;
            else if (c == '{' || c == '[') depth++;
            else if ((c == '}' || c == ']') && --depth == 0) {
                i++;
                return s.substring(start, i);
            }
        }
        throw new IllegalArgumentException("Unclosed object");
    }

    private String string() {
        expect('"');
        StringBuilder b = new StringBuilder();
        while (true) {
            char c = next();
            if (c == '"') return b.toString();
            if (c != '\\') {
                b.append(c);
                continue;
            }
            char e = next();
            switch (e) {
                case 'n' -> b.append('\n');
                case 't' -> b.append('\t');
                case 'r' -> b.append('\r');
                case 'b' -> b.append('\b');
                case 'f' -> b.append('\f');
                case 'u' -> {
                    b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    i += 4;
                }
                default -> b.append(e);
            }
        }
    }

    private void ws() {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
    }

    private char peek() {
        if (i >= s.length()) throw new IllegalArgumentException("Unexpected end");
        return s.charAt(i);
    }

    private char next() {
        char c = peek();
        i++;
        return c;
    }

    private void expect(char c) {
        if (next() != c) throw new IllegalArgumentException("Expected " + c + " at " + (i - 1));
    }
}
