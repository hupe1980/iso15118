import com.siemens.ct.exi.core.grammars.Grammars;
import com.siemens.ct.exi.core.grammars.grammar.Grammar;
import com.siemens.ct.exi.core.grammars.production.Production;
import com.siemens.ct.exi.core.grammars.event.*;
import com.siemens.ct.exi.grammars.GrammarFactory;

import java.util.*;

/**
 * Dumps exificient's derived schema-informed grammar as a flat graph, in the
 * same canonical form `iso15118-codegen --dump` emits, so the two can be
 * diffed. See tools/compare_grammars.py in the iso15118 repository.
 *
 * usage: GrammarDump <schema.xsd>
 */
public class GrammarDump {
    static Map<Grammar, Integer> ids = new IdentityHashMap<>();
    static List<Grammar> order = new ArrayList<>();

    static int id(Grammar g) {
        Integer existing = ids.get(g);
        if (existing != null) return existing;
        int n = order.size();
        ids.put(g, n);
        order.add(g);
        return n;
    }

    static String qname(javax.xml.namespace.QName q) {
        return "{" + q.getNamespaceURI() + "}" + q.getLocalPart();
    }

    public static void main(String[] args) throws Exception {
        Grammars g = GrammarFactory.newInstance().createGrammars(args[0]);

        // The document grammar's content state lists every global element; its
        // production bodies are the element grammars we want to compare.
        Grammar doc = g.getDocumentGrammar();
        Grammar content = doc.getProduction(0).getNextGrammar();

        StringBuilder index = new StringBuilder();
        List<Grammar> roots = new ArrayList<>();
        for (int c = 0; c < content.getNumberOfEvents(); c++) {
            Event e = content.getProduction(c).getEvent();
            if (e instanceof StartElement se && se.getGrammar() != null) {
                int gid = id(se.getGrammar());
                index.append("#element ").append(qname(se.getQName())).append(" G").append(gid).append("\n");
                roots.add(se.getGrammar());
            }
        }

        // Expand every grammar reachable from those roots.
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < order.size(); i++) {
            Grammar cur = order.get(i);
            StringBuilder sb = new StringBuilder();
            sb.append("G").append(i).append(" events=").append(cur.getNumberOfEvents()).append("\n");
            for (int c = 0; c < cur.getNumberOfEvents(); c++) {
                Production p = cur.getProduction(c);
                Event e = p.getEvent();
                sb.append("  ").append(c).append(" ");
                switch (e.getEventType()) {
                    case START_ELEMENT, START_ELEMENT_NS -> {
                        StartElement se = (StartElement) e;
                        sb.append("SE ").append(qname(se.getQName()))
                          .append(" body=G").append(id(se.getGrammar()))
                          .append(" -> G").append(id(p.getNextGrammar())).append("\n");
                    }
                    case ATTRIBUTE -> {
                        Attribute at = (Attribute) e;
                        sb.append("AT ").append(qname(at.getQName()))
                          .append(" -> G").append(id(p.getNextGrammar())).append("\n");
                    }
                    case CHARACTERS -> sb.append("CH -> G").append(id(p.getNextGrammar())).append("\n");
                    case CHARACTERS_GENERIC -> sb.append("CHGEN -> G").append(id(p.getNextGrammar())).append("\n");
                    case START_ELEMENT_GENERIC -> sb.append("SEGEN -> G").append(id(p.getNextGrammar())).append("\n");
                    case END_ELEMENT -> sb.append("EE\n");
                    default -> sb.append(e.getEventType()).append("\n");
                }
            }
            body.append(sb);
        }

        System.out.print(index);
        System.out.print(body);
    }
}
