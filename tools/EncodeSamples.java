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
 * Encodes every XML instance in a directory with the ISO 15118 EXI profile —
 * schema-informed, bit-packed, default fidelity options — and prints
 * "name hex" lines for the Rust side to check against.
 *
 * usage: EncodeSamples <schema.xsd> <sample-dir>
 */
public class EncodeSamples {
    public static void main(String[] args) throws Exception {
        EXIFactory ef = DefaultEXIFactory.newInstance();
        ef.setGrammars(GrammarFactory.newInstance().createGrammars(args[0]));
        ef.setCodingMode(CodingMode.BIT_PACKED);
        ef.setFidelityOptions(FidelityOptions.createDefault());

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
