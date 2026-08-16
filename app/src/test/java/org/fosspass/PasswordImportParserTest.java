package org.fosspass;

import static org.junit.Assert.assertEquals;

import java.util.List;
import org.junit.Test;

public class PasswordImportParserTest {
    @Test
    public void parsesLastPassCsvIncludingExtraNotes() throws Exception {
        String csv = "url,username,password,extra,name,grouping,fav\n"
                + "https://example.com,alice,secret,personal note,Example,Work,0\n";
        List<PasswordImportParser.ImportedEntry> entries = PasswordImportParser.parse(csv);
        assertEquals(1, entries.size());
        assertEquals("Example", entries.get(0).title);
        assertEquals("personal note", entries.get(0).notes);
    }

    @Test
    public void parsesDashlaneCsvAliases() throws Exception {
        String csv = "username,username2,username3,title,password,note,url,category\n"
                + "alice,backup,,Dashlane Login,secret,from dashlane,https://dash.example,login\n";
        PasswordImportParser.ImportedEntry entry = PasswordImportParser.parse(csv).get(0);
        assertEquals("alice", entry.username);
        assertEquals("Dashlane Login", entry.title);
        assertEquals("from dashlane", entry.notes);
    }

    @Test
    public void parsesProtonPassCsv() throws Exception {
        String csv = "name,url,username,password,note,vault,type\n"
                + "Proton Item,https://proton.example,bob,hunter2,proton note,Personal,login\n";
        PasswordImportParser.ImportedEntry entry = PasswordImportParser.parse(csv).get(0);
        assertEquals("Proton Item", entry.title);
        assertEquals("proton note", entry.notes);
    }

    @Test
    public void parsesBitwardenJsonLogin() throws Exception {
        String json = "{\"items\":[{\"type\":1,\"name\":\"Bitwarden\",\"notes\":\"note\","
                + "\"login\":{\"username\":\"carol\",\"password\":\"secret\","
                + "\"uris\":[{\"uri\":\"https://bitwarden.example\"}]}}]}";
        PasswordImportParser.ImportedEntry entry = PasswordImportParser.parse(json).get(0);
        assertEquals("Bitwarden", entry.title);
        assertEquals("carol", entry.username);
        assertEquals("https://bitwarden.example", entry.url);
    }

    @Test
    public void parsesKeePassXmlAndDisablesDoctype() throws Exception {
        String xml = "<KeePassFile><Root><Group><Entry>"
                + "<String><Key>Title</Key><Value>KeePass</Value></String>"
                + "<String><Key>UserName</Key><Value>dave</Value></String>"
                + "<String><Key>Password</Key><Value>secret</Value></String>"
                + "</Entry></Group></Root></KeePassFile>";
        PasswordImportParser.ImportedEntry entry = PasswordImportParser.parse(xml).get(0);
        assertEquals("KeePass", entry.title);
        assertEquals("dave", entry.username);
    }

    @Test
    public void ignoresKeePassPasswordHistoryEntries() throws Exception {
        String xml = "<KeePassFile><Root><Group><Entry>"
                + "<String><Key>Title</Key><Value>Current</Value></String>"
                + "<String><Key>UserName</Key><Value>alice</Value></String>"
                + "<String><Key>Password</Key><Value>current-secret</Value></String>"
                + "<History><Entry>"
                + "<String><Key>Title</Key><Value>Historical</Value></String>"
                + "<String><Key>Password</Key><Value>old-secret</Value></String>"
                + "</Entry></History>"
                + "</Entry></Group></Root></KeePassFile>";
        List<PasswordImportParser.ImportedEntry> entries = PasswordImportParser.parse(xml);
        assertEquals(1, entries.size());
        assertEquals("Current", entries.get(0).title);
        assertEquals("current-secret", entries.get(0).password);
    }

    @Test
    public void derivesFirefoxEntryTitleFromUrl() throws Exception {
        String csv = "url,username,password,httpRealm,formActionOrigin,guid\n"
                + "https://accounts.example.com/login,erin,secret,,,id-1\n";
        PasswordImportParser.ImportedEntry entry = PasswordImportParser.parse(csv).get(0);
        assertEquals("accounts.example.com", entry.title);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsUnterminatedQuotedCsvField() throws Exception {
        PasswordImportParser.parse("name,username,password\n\"broken,alice,secret\n");
    }
}
