#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>
#include <libxml/xmlmemory.h>

/* Include the module implementation that contains the static
 * xmlRelaxNGParseExceptNameClass implementation so the harness can
 * call it from the same translation unit.
 *
 * The included source is part of the project and defines the function
 * we want to fuzz. Including the .c file here puts that static function
 * into this TU (so it's callable from below).
 */
#include "../relaxng.c"

// One-time initialization
static void ensure_libxml_initialized(void) {
    static int inited = 0;
    if (inited) return;
    xmlInitParser();
    /*
     * Disable global pedantic error messages during fuzzing; libxml functions
     * used below request no stderr/no warnings via parse options when possible.
     */
    inited = 1;
}

// Helper: depth-first search for an <except> element in the relax-ng namespace
static xmlNodePtr find_relaxng_except(xmlNodePtr node) {
    if (node == NULL) return NULL;
    xmlNodePtr cur = node;
    // stackless recursion using explicit stack could be used; a simple recursion is fine here.
    for (; cur != NULL; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE && cur->name != NULL) {
            if (xmlStrEqual(cur->name, (const xmlChar *)"except") &&
                cur->ns != NULL &&
                cur->ns->href != NULL &&
                xmlStrEqual(cur->ns->href, (const xmlChar *)"http://relaxng.org/ns/structure/1.0")) {
                return cur;
            }
            // search children
            xmlNodePtr found = find_relaxng_except(cur->children);
            if (found) return found;
        } else {
            // try children for non-element nodes as well
            xmlNodePtr found = find_relaxng_except(cur->children);
            if (found) return found;
        }
    }
    return NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    ensure_libxml_initialized();

    // Quick guard
    if (Data == NULL || Size == 0) {
        return 0;
    }

    // Create a parser context for relax-ng parsing routines.
    // xmlRelaxNGNewParserCtxt expects a non-NULL URL string.
    xmlRelaxNGParserCtxtPtr pctxt = xmlRelaxNGNewParserCtxt("fuzz://input");
    if (pctxt == NULL) {
        return 0;
    }

    // Try to parse Data as an XML document first
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size,
                                  "fuzz-input.xml", NULL,
                                  XML_PARSE_RECOVER | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    xmlNodePtr target = NULL;

    if (doc != NULL) {
        xmlNodePtr root = xmlDocGetRootElement(doc);
        if (root != NULL) {
            target = find_relaxng_except(root);
        }
    }

    // If no valid <except> node found in the parsed doc, synthesize one
    if (target == NULL) {
        // Drop parsed doc (if any) and create a synthetic one
        if (doc != NULL) {
            xmlFreeDoc(doc);
            doc = NULL;
        }
        doc = xmlNewDoc((const xmlChar *)"1.0");
        if (doc == NULL) {
            xmlRelaxNGFreeParserCtxt(pctxt);
            return 0;
        }
        // Create an <except> node in the Relax-NG namespace
        target = xmlNewDocNode(doc, NULL, (const xmlChar *)"except", NULL);
        if (target == NULL) {
            xmlFreeDoc(doc);
            xmlRelaxNGFreeParserCtxt(pctxt);
            return 0;
        }
        // Ensure the node has the Relax-NG namespace
        xmlNewNs(target, (const xmlChar *)"http://relaxng.org/ns/structure/1.0", NULL);
        xmlDocSetRootElement(doc, target);

        // Use fuzz bytes to create 1..4 child elements (name/anyName/nsName/choice)
        size_t idx = 0;
        size_t nchild = 1 + (Data[idx] % 4);
        idx++;
        const char *choices[4] = { "name", "anyName", "nsName", "choice" };
        for (size_t i = 0; i < nchild; i++) {
            int sel = Data[idx % Size] % 4;
            idx++;
            xmlNodePtr ch = xmlNewChild(target, NULL, (const xmlChar *)choices[sel], NULL);
            if (ch == NULL) continue;
            // Put the namespace on the child as well
            xmlNewNs(ch, (const xmlChar *)"http://relaxng.org/ns/structure/1.0", NULL);

            // If nsName, set an 'ns' attribute (random small string derived from fuzz bytes)
            if (sel == 2) {
                char nsBuf[64];
                size_t n = (size_t)(Data[idx % Size] % 10);
                idx++;
                // Build a simple string from following bytes (printable subset)
                for (size_t b = 0; b < n && b < sizeof(nsBuf)-1; b++) {
                    unsigned char v = Data[idx % Size];
                    idx++;
                    char c = (char)((v % 26) + 'a');
                    nsBuf[b] = c;
                }
                nsBuf[(n < sizeof(nsBuf)-1) ? n : (sizeof(nsBuf)-1)] = '\0';
                xmlNewProp(ch, (const xmlChar *)"ns", (const xmlChar *)nsBuf);
            } else if (sel == 0) {
                // for <name> add textual content from fuzz
                char txt[64];
                size_t n = (size_t)((Data[idx % Size] % 15) + 1);
                idx++;
                for (size_t b = 0; b < n && b < sizeof(txt)-1; b++) {
                    unsigned char v = Data[idx % Size];
                    idx++;
                    char c = (char)((v % 26) + 'a');
                    txt[b] = c;
                }
                txt[(n < sizeof(txt)-1) ? n : (sizeof(txt)-1)] = '\0';
                xmlNodeSetContent(ch, (const xmlChar *)txt);
            }
        }
    }

    // Decide 'attr' flag from first byte (0 or 1)
    int attr = (Data[0] & 1) ? 1 : 0;

    // Call the target function. It returns an xmlRelaxNGDefinePtr (may be NULL).
    (void) xmlRelaxNGParseExceptNameClass(pctxt, target, attr);

    // Cleanup local resources
    xmlRelaxNGFreeParserCtxt(pctxt);
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    // Do not call xmlCleanupParser() here as it cleans global state useful for
    // subsequent iterations in many fuzzing setups.

    return 0;
}
