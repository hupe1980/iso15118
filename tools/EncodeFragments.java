import com.siemens.ct.exi.core.*;
import com.siemens.ct.exi.core.helpers.DefaultEXIFactory;
import com.siemens.ct.exi.grammars.GrammarFactory;
import com.siemens.ct.exi.main.api.sax.EXIResult;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * The same as {@link EncodeSamples}, but encoding each instance as an EXI
 * <em>fragment</em> (EXI 1.0 §8.5.2) rather than as a document.
 *
 * <p>This is the form ISO 15118 signs. A fragment is indexed by every element
 * qname the schema set declares — local declarations included — which is a
 * different and much longer table than the global-element list a document is
 * indexed by, so the two encodings of the same element differ in their very
 * first event code. Nothing but a reference implementation settles which table
 * is right.
 *
 * <p>usage: EncodeFragments &lt;schema.xsd&gt; &lt;sample-dir&gt;
 */
public class EncodeFragments {
    public static void main(String[] args) throws Exception {
        EXIFactory ef = DefaultEXIFactory.newInstance();
        ef.setGrammars(GrammarFactory.newInstance().createGrammars(args[0]));
        ef.setCodingMode(CodingMode.BIT_PACKED);
        ef.setFidelityOptions(FidelityOptions.createDefault());
        ef.setFragment(true);

        javax.xml.parsers.SAXParserFactory spf = javax.xml.parsers.SAXParserFactory.newInstance();
        spf.setNamespaceAware(true);

        List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> dir = Files.newDirectoryStream(Paths.get(args[1]), "*.xml")) {
            for (Path p : dir) files.add(p);
        }
        Collections.sort(files);

        for (Path file : files) {
            String name = file.getFileName().toString().replace(".xml", "");
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                EXIResult res = new EXIResult(ef);
                res.setOutputStream(bos);
                XMLReader rd = spf.newSAXParser().getXMLReader();
                rd.setContentHandler(res.getHandler());
                rd.parse(new InputSource(Files.newInputStream(file)));
                StringBuilder hex = new StringBuilder();
                for (byte b : bos.toByteArray()) hex.append(String.format("%02x", b));
                System.out.println(name + " " + hex);
            } catch (Exception e) {
                System.err.println("skip " + name + ": " + e.getMessage());
            }
        }
    }
}
