import com.siemens.ct.exi.core.*;
import com.siemens.ct.exi.core.helpers.DefaultEXIFactory;
import com.siemens.ct.exi.grammars.GrammarFactory;
import com.siemens.ct.exi.main.api.sax.EXISource;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import javax.xml.transform.*;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;

/**
 * Decodes an EXI stream given as hex back to XML, using the ISO 15118 profile.
 * The quickest way to find out what a byte string actually says.
 *
 * usage: DecodeHex <schema.xsd> <hex>
 */
public class DecodeHex {
    public static void main(String[] args) throws Exception {
        EXIFactory ef = DefaultEXIFactory.newInstance();
        ef.setGrammars(GrammarFactory.newInstance().createGrammars(args[0]));
        ef.setCodingMode(CodingMode.BIT_PACKED);
        ef.setFidelityOptions(FidelityOptions.createDefault());

        String hex = args[1];
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++)
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);

        EXISource src = new EXISource(ef);
        XMLReader reader = src.getXMLReader();
        SAXSource sax = new SAXSource(new InputSource(new ByteArrayInputStream(bytes)));
        sax.setXMLReader(reader);
        StringWriter sw = new StringWriter();
        Transformer t = TransformerFactory.newInstance().newTransformer();
        t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        t.transform(sax, new StreamResult(sw));
        System.out.println(sw);
    }
}
