package org.fosspass;

import org.json.JSONArray;
import org.json.JSONObject;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.DocumentBuilderFactory;

final class PasswordImportParser {
    private static final int MAX_IMPORT_ENTRIES = 50_000;
    private static final int MAX_FIELD_CHARS = 1_000_000;

    static final class ImportedEntry {
        final String title;
        final String username;
        final String password;
        final String url;
        final String notes;

        ImportedEntry(String title, String username, String password, String url, String notes) {
            this.title = checkedField(displayTitle(title, url));
            this.username = checkedField(value(username));
            this.password = checkedField(value(password));
            this.url = checkedField(value(url));
            this.notes = checkedField(value(notes));
        }
    }

    private PasswordImportParser() {}

    static List<ImportedEntry> parse(String content) throws Exception {
        String trimmed = content == null ? "" : content.trim();
        if (trimmed.isEmpty()) return new ArrayList<>();
        if (trimmed.startsWith("<")) return parseKeePassXml(content);
        if (trimmed.startsWith("[") || trimmed.startsWith("{")) return parseJson(trimmed);
        return parseCsv(content);
    }

    private static List<ImportedEntry> parseJson(String content) throws Exception {
        JSONArray array;
        if (content.startsWith("[")) {
            array = new JSONArray(content);
        } else {
            JSONObject root = new JSONObject(content);
            array = root.optJSONArray("items");
            if (array == null) array = root.optJSONArray("entries");
            if (array == null) array = root.optJSONArray("accounts");
            if (array == null) throw new IllegalArgumentException("Unsupported JSON password-manager export");
        }
        if (array.length() > MAX_IMPORT_ENTRIES) {
            throw new IllegalArgumentException("Import contains too many entries");
        }

        List<ImportedEntry> result = new ArrayList<>();
        for (int i = 0; i < array.length(); i++) {
            JSONObject item = array.optJSONObject(i);
            if (item == null) continue;
            String title = first(item, "name", "title", "service", "hostname");
            String username = first(item, "username", "user", "login", "email");
            String password = first(item, "password", "pass");
            String url = first(item, "url", "website", "uri", "login_uri");
            String notes = first(item, "notes", "note", "extra");

            JSONObject login = item.optJSONObject("login");
            if (login != null) {
                username = firstNonBlank(first(login, "username", "user", "email"), username);
                password = firstNonBlank(first(login, "password", "pass"), password);
                url = firstNonBlank(first(login, "url", "website", "uri"), url);
                JSONArray uris = login.optJSONArray("uris");
                if (blank(url) && uris != null && uris.length() > 0) {
                    JSONObject firstUri = uris.optJSONObject(0);
                    if (firstUri != null) url = first(firstUri, "uri", "url");
                }
            }
            result.add(new ImportedEntry(title, username, password, url, notes));
        }
        return result;
    }

    private static List<ImportedEntry> parseCsv(String content) {
        List<List<String>> rows = parseCsvRows(content);
        List<ImportedEntry> result = new ArrayList<>();
        if (rows.isEmpty()) return result;
        if (rows.size() - 1 > MAX_IMPORT_ENTRIES) {
            throw new IllegalArgumentException("Import contains too many entries");
        }

        List<String> header = rows.get(0);
        int title = column(header, "name", "title", "service", "hostname", "account");
        int username = column(header, "username", "user", "login", "login_username", "email");
        int password = column(header, "password", "pass", "login_password");
        int url = column(header, "url", "website", "uri", "login_uri", "origin");
        int notes = column(header, "notes", "note", "extra", "comments", "description");

        if (title < 0 && username < 0 && password < 0 && url < 0) {
            throw new IllegalArgumentException("Unsupported CSV headers");
        }

        for (int i = 1; i < rows.size(); i++) {
            List<String> row = rows.get(i);
            if (row.size() == 1 && blank(row.get(0))) continue;
            result.add(new ImportedEntry(
                    cell(row, title), cell(row, username), cell(row, password),
                    cell(row, url), cell(row, notes)));
        }
        return result;
    }

    private static List<ImportedEntry> parseKeePassXml(String content) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

        NodeList entryNodes = factory.newDocumentBuilder()
                .parse(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)))
                .getElementsByTagName("Entry");
        if (entryNodes.getLength() > MAX_IMPORT_ENTRIES) {
            throw new IllegalArgumentException("Import contains too many entries");
        }
        List<ImportedEntry> result = new ArrayList<>();
        for (int i = 0; i < entryNodes.getLength(); i++) {
            Element entry = (Element) entryNodes.item(i);
            if (hasAncestor(entry, "History")) continue;
            Map<String, String> values = new HashMap<>();
            NodeList children = entry.getChildNodes();
            for (int j = 0; j < children.getLength(); j++) {
                Node child = children.item(j);
                if (child.getNodeType() != Node.ELEMENT_NODE
                        || !"String".equals(((Element) child).getTagName())) continue;
                Element string = (Element) child;
                values.put(directChildText(string, "Key"), directChildText(string, "Value"));
            }
            result.add(new ImportedEntry(
                    values.get("Title"), values.get("UserName"), values.get("Password"),
                    values.get("URL"), values.get("Notes")));
        }
        return result;
    }

    private static List<List<String>> parseCsvRows(String text) {
        List<List<String>> rows = new ArrayList<>();
        List<String> row = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (quoted) {
                if (c == '"' && i + 1 < text.length() && text.charAt(i + 1) == '"') {
                    field.append('"');
                    i++;
                } else if (c == '"') {
                    quoted = false;
                } else {
                    field.append(c);
                }
            } else if (c == '"') {
                quoted = true;
            } else if (c == ',') {
                row.add(field.toString());
                field.setLength(0);
            } else if (c == '\n') {
                row.add(field.toString());
                field.setLength(0);
                rows.add(row);
                row = new ArrayList<>();
            } else if (c != '\r') {
                field.append(c);
            }
        }
        if (quoted) throw new IllegalArgumentException("Malformed CSV: unterminated quoted field");
        row.add(field.toString());
        if (!(row.size() == 1 && row.get(0).isEmpty())) rows.add(row);
        return rows;
    }

    private static String first(JSONObject object, String... names) {
        for (String name : names) {
            String candidate = object.optString(name, "");
            if (!blank(candidate)) return candidate;
        }
        return "";
    }

    private static int column(List<String> header, String... names) {
        for (int i = 0; i < header.size(); i++) {
            String normalized = header.get(i).replace("\uFEFF", "").trim();
            for (String name : names) if (normalized.equalsIgnoreCase(name)) return i;
        }
        return -1;
    }

    private static String cell(List<String> row, int index) {
        return index >= 0 && index < row.size() ? row.get(index) : "";
    }

    private static boolean hasAncestor(Element element, String tag) {
        Node parent = element.getParentNode();
        while (parent != null) {
            if (parent.getNodeType() == Node.ELEMENT_NODE
                    && tag.equals(((Element) parent).getTagName())) return true;
            parent = parent.getParentNode();
        }
        return false;
    }

    private static String directChildText(Element parent, String tag) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE
                    && tag.equals(((Element) child).getTagName())) return child.getTextContent();
        }
        return "";
    }

    private static String firstNonBlank(String first, String second) {
        return blank(first) ? value(second) : first;
    }

    private static String displayTitle(String title, String url) {
        if (!blank(title)) return title;
        if (!blank(url)) {
            try {
                String host = URI.create(url.trim()).getHost();
                if (!blank(host)) return host;
            } catch (IllegalArgumentException ignored) {}
        }
        return "Imported";
    }

    private static boolean blank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static String value(String value) {
        return value == null ? "" : value;
    }

    private static String checkedField(String value) {
        if (value.length() > MAX_FIELD_CHARS) {
            throw new IllegalArgumentException("Import field exceeds safety limit");
        }
        return value;
    }
}
