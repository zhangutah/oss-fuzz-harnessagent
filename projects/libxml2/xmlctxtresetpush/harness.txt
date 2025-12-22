// Generate a fuzz driver based the given function signature in C language. Output the full driver code in reply.
//  You can call the following tools to get more information about the code.
//  Prefer higher-priority tools first; only use view_code when you already know the exact file path and a line number:
//  
//  1) get_symbol_header_tool — Get the header file(s) needed for a symbol. Try an absolute path first (e.g., #include "/path/to/header.h"). If that fails with ".h file not found", try a project-relative path.
//  2) get_symbol_definition_tool — Get the definition of a symbol (the function body or struct/class definition).
//  3) get_symbol_declaration_tool — Get the declaration (prototype/signature) of a symbol.
//  4) get_symbol_references_tool — Get the references/usage of a symbol within the codebase.
//  5) get_struct_related_functions_tool — Get helper functions that operate on a struct/class (e.g., init, destroy, setters/getters).
//  6) view_code — View code around a specific file path and target line. Use this only when the path and line are known; keep context_window small.
//  7) get_file_location_tool - Get the absolute path of a file in the project codebase.
//  8) get_driver_example_tool - Randomly select one harness file in the container and return its content. 
// 
//  Guardrails:
//  - Don't call view_code repeatedly to browse; instead, first retrieve definitions/headers/references to precisely locate what you need.
//  - Avoid requesting huge windows; stay within a small context_window unless specifically needed.
// 
// @ examples of API usage:
// // Example 1:
// 
// // int
// //xmllintMain(int argc, const char **argv, FILE *errStream,
// //            xmlResourceLoader loader) {
// //    xmllintState state, *lint;
// //    int i, j, res;
// //    int files = 0;
// //
// //#ifdef _WIN32
// //    _setmode(_fileno(stdin), _O_BINARY);
// //    _setmode(_fileno(stdout), _O_BINARY);
// //    _setmode(_fileno(stderr), _O_BINARY);
// //#endif
// //
// //    lint = &state;
// //    xmllintInit(lint);
// //    lint->errStream = errStream;
// //    lint->defaultResourceLoader = loader;
// //
// //    res = xmllintParseOptions(lint, argc, argv);
// //    if (res != XMLLINT_RETURN_OK) {
// //        return(res);
// //    }
// //
// //    /*
// //     * Note that we must not make any memory allocations through xmlMalloc
// //     * before calling xmlMemSetup.
// //     */
// //    if (lint->maxmem != 0) {
// //        xmllintMaxmem = 0;
// //        xmllintMaxmemReached = 0;
// //        xmllintOom = 0;
// //        xmlMemSetup(myFreeFunc, myMallocFunc, myReallocFunc, myStrdupFunc);
// //    }
// //
// //    LIBXML_TEST_VERSION
// //
// //#ifdef LIBXML_CATALOG_ENABLED
// //    if ((lint->appOptions & XML_LINT_USE_NO_CATALOGS) != XML_LINT_USE_NO_CATALOGS) {
// //	if (lint->appOptions & XML_LINT_USE_CATALOGS) {
// //	    const char *catal;
// //
// //	    catal = getenv("SGML_CATALOG_FILES");
// //	    if (catal != NULL) {
// //		xmlLoadCatalogs(catal);
// //	    } else {
// //		fprintf(errStream, "Variable $SGML_CATALOG_FILES not set\n");
// //	    }
// //	}
// //    }
// //#endif
// //
// //#ifdef LIBXML_OUTPUT_ENABLED
// //    {
// //        const char *indent = getenv("XMLLINT_INDENT");
// //        if (indent != NULL) {
// //            lint->indentString = indent;
// //        }
// //    }
// //#endif
// //
// //#ifdef LIBXML_SCHEMATRON_ENABLED
// //    if ((lint->schematron != NULL) && ((lint->appOptions & XML_LINT_SAX_ENABLED) != XML_LINT_SAX_ENABLED)
// //#ifdef LIBXML_READER_ENABLED
// //        && ((lint->appOptions & XML_LINT_USE_STREAMING) != XML_LINT_USE_STREAMING)
// //#endif /* LIBXML_READER_ENABLED */
// //	) {
// //	xmlSchematronParserCtxtPtr ctxt;
// //
// //        /* forces loading the DTDs */
// //	lint->parseOptions |= XML_PARSE_DTDLOAD;
// //	if (lint->appOptions & XML_LINT_TIMINGS) {
// //	    startTimer(lint);
// //	}
// //	ctxt = xmlSchematronNewParserCtxt(lint->schematron);
// //        if (ctxt == NULL) {
// //            lint->progresult = XMLLINT_ERR_MEM;
// //            goto error;
// //        }
// //	lint->wxschematron = xmlSchematronParse(ctxt);
// //	xmlSchematronFreeParserCtxt(ctxt);
// //	if (lint->wxschematron == NULL) {
// //	    fprintf(errStream, "Schematron schema %s failed to compile\n",
// //                    lint->schematron);
// //            lint->progresult = XMLLINT_ERR_SCHEMACOMP;
// //            goto error;
// //	}
// //	if (lint->appOptions & XML_LINT_TIMINGS) {
// //	    endTimer(lint, "Compiling the schemas");
// //	}
// //    }
// //#endif
// //
// //#ifdef LIBXML_RELAXNG_ENABLED
// //    if ((lint->relaxng != NULL) && ((lint->appOptions & XML_LINT_SAX_ENABLED) != XML_LINT_SAX_ENABLED)
// //#ifdef LIBXML_READER_ENABLED
// //        && ((lint->appOptions & XML_LINT_USE_STREAMING) != XML_LINT_USE_STREAMING)
// //#endif /* LIBXML_READER_ENABLED */
// //	) {
// //	xmlRelaxNGParserCtxtPtr ctxt;
// //
// //        /* forces loading the DTDs */
// //	lint->parseOptions |= XML_PARSE_DTDLOAD;
// //	if (lint->appOptions & XML_LINT_TIMINGS) {
// //	    startTimer(lint);
// //	}
// //	ctxt = xmlRelaxNGNewParserCtxt(lint->relaxng);
// //        if (ctxt == NULL) {
// //            lint->progresult = XMLLINT_ERR_MEM;
// //            goto error;
// //        }
// //        xmlRelaxNGSetResourceLoader(ctxt, xmllintResourceLoader, lint);
// //	lint->relaxngschemas = xmlRelaxNGParse(ctxt);
// //	xmlRelaxNGFreeParserCtxt(ctxt);
// //	if (lint->relaxngschemas == NULL) {
// //	    fprintf(errStream, "Relax-NG schema %s failed to compile\n",
// //                    lint->relaxng);
// //            lint->progresult = XMLLINT_ERR_SCHEMACOMP;
// //            goto error;
// //	}
// //	if (lint->appOptions & XML_LINT_TIMINGS) {
// //	    endTimer(lint, "Compiling the schemas");
// //	}
// //    }
// //#endif /* LIBXML_RELAXNG_ENABLED */
// //
// //#ifdef LIBXML_SCHEMAS_ENABLED
// //    if ((lint->schema != NULL)
// //#ifdef LIBXML_READER_ENABLED
// //        && ((lint->appOptions& XML_LINT_USE_STREAMING) != XML_LINT_USE_STREAMING)
// //#endif
// //	) {
// //	xmlSchemaParserCtxtPtr ctxt;
// //
// //	if (lint->appOptions & XML_LINT_TIMINGS) {
// //	    startTimer(lint);
// //	}
// //	ctxt = xmlSchemaNewParserCtxt(lint->schema);
// //        if (ctxt == NULL) {
// //            lint->progresult = XMLLINT_ERR_MEM;
// //            goto error;
// //        }
// //        xmlSchemaSetResourceLoader(ctxt, xmllintResourceLoader, lint);
// //	lint->wxschemas = xmlSchemaParse(ctxt);
// //	xmlSchemaFreeParserCtxt(ctxt);
// //	if (lint->wxschemas == NULL) {
// //	    fprintf(errStream, "WXS schema %s failed to compile\n",
// //                    lint->schema);
// //            lint->progresult = XMLLINT_ERR_SCHEMACOMP;
// //            goto error;
// //	}
// //	if (lint->appOptions & XML_LINT_TIMINGS) {
// //	    endTimer(lint, "Compiling the schemas");
// //	}
// //    }
// //#endif /* LIBXML_SCHEMAS_ENABLED */
// //
// //#if defined(LIBXML_READER_ENABLED) && defined(LIBXML_PATTERN_ENABLED)
// //    if ((lint->pattern != NULL) && ((lint->appOptions & XML_LINT_USE_WALKER) != XML_LINT_USE_WALKER)) {
// //        res = xmlPatternCompileSafe(BAD_CAST lint->pattern, NULL, 0, NULL,
// //                                    &lint->patternc);
// //	if (lint->patternc == NULL) {
// //            if (res < 0) {
// //                lint->progresult = XMLLINT_ERR_MEM;
// //            } else {
// //                fprintf(errStream, "Pattern %s failed to compile\n",
// //                        lint->pattern);
// //                lint->progresult = XMLLINT_ERR_SCHEMAPAT;
// //            }
// //            goto error;
// //	}
// //    }
// //#endif /* LIBXML_READER_ENABLED && LIBXML_PATTERN_ENABLED */
// //
// //    /*
// //     * The main loop over input documents
// //     */
// //    for (i = 1; i < argc ; i++) {
// //        const char *filename = argv[i];
// //#if HAVE_DECL_MMAP
// //        int memoryFd = -1;
// //#endif
// //
// //	if ((filename[0] == '-') && (strcmp(filename, "-") != 0)) {
// //            i += skipArgs(filename);
// //            continue;
// //        }
// //
// //#if HAVE_DECL_MMAP
// //        if (lint->appOptions & XML_LINT_MEMORY) {
// //            struct stat info;
// //            if (stat(filename, &info) < 0) {
// //                lint->progresult = XMLLINT_ERR_RDFILE;
// //                break;
// //            }
// //            memoryFd = open(filename, O_RDONLY);
// //            if (memoryFd < 0) {
// //                lint->progresult = XMLLINT_ERR_RDFILE;
// //                break;
// //            }
// //            lint->memoryData = mmap(NULL, info.st_size, PROT_READ,
// //                                    MAP_SHARED, memoryFd, 0);
// //            if (lint->memoryData == (void *) MAP_FAILED) {
// //                close(memoryFd);
// //                fprintf(errStream, "mmap failure for file %s\n", filename);
// //                lint->progresult = XMLLINT_ERR_RDFILE;
// //                break;
// //            }
// //            lint->memorySize = info.st_size;
// //        }
// //#endif /* HAVE_DECL_MMAP */
// //
// //	if ((lint->appOptions & XML_LINT_TIMINGS) && (lint->repeat > 1))
// //	    startTimer(lint);
// //
// //#ifdef LIBXML_READER_ENABLED
// //        if (lint->appOptions & XML_LINT_USE_STREAMING) {
// //            for (j = 0; j < lint->repeat; j++)
// //                streamFile(lint, filename);
// //        } else
// //#endif /* LIBXML_READER_ENABLED */
// //        {
// //            xmlParserCtxtPtr ctxt;
// //
// //#ifdef LIBXML_HTML_ENABLED
// //            if (lint->appOptions & XML_LINT_HTML_ENABLED) {
// //#ifdef LIBXML_PUSH_ENABLED
// //                if (lint->appOptions & XML_LINT_PUSH_ENABLED) {
// //                    ctxt = htmlCreatePushParserCtxt(NULL, NULL, NULL, 0,
// //                                                    filename,
// //                                                    XML_CHAR_ENCODING_NONE);
// //                } else
// //#endif /* LIBXML_PUSH_ENABLED */
// //                {
// //                    ctxt = htmlNewParserCtxt();
// //                }
// //                htmlCtxtUseOptions(ctxt, lint->htmlOptions);
// //            } else
// //#endif /* LIBXML_HTML_ENABLED */
// //            {
// //#ifdef LIBXML_PUSH_ENABLED
// //                if (lint->appOptions & XML_LINT_PUSH_ENABLED) {
// //                    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0,
// //                                                   filename);
// //                } else
// //#endif /* LIBXML_PUSH_ENABLED */
// //                {
// //                    ctxt = xmlNewParserCtxt();
// //                }
// //                xmlCtxtUseOptions(ctxt, lint->parseOptions);
// //            }
// //            if (ctxt == NULL) {
// //                lint->progresult = XMLLINT_ERR_MEM;
// //                goto error;
// //            }
// //
// //            if (lint->appOptions & XML_LINT_SAX_ENABLED) {
// //                const xmlSAXHandler *handler;
// //
// //                if (lint->noout) {
// //                    handler = &emptySAXHandler;
// //#ifdef LIBXML_SAX1_ENABLED
// //                } else if (lint->parseOptions & XML_PARSE_SAX1) {
// //                    handler = &debugSAXHandler;
// //#endif
// //                } else {
// //                    handler = &debugSAX2Handler;
// //                }
// //
// //                *ctxt->sax = *handler;
// //                ctxt->userData = lint;
// //            }
// //
// //            xmlCtxtSetResourceLoader(ctxt, xmllintResourceLoader, lint);
// //            if (lint->maxAmpl > 0)
// //                xmlCtxtSetMaxAmplification(ctxt, lint->maxAmpl);
// //
// //            lint->ctxt = ctxt;
// //
// //            for (j = 0; j < lint->repeat; j++) {
// //                if (j > 0) {
// //#ifdef LIBXML_PUSH_ENABLED
// //                    if (lint->appOptions & XML_LINT_PUSH_ENABLED) {
// //                        xmlCtxtResetPush(ctxt, NULL, 0, NULL, NULL);
// //                    } else
// //#endif
// //                    {
// //                        xmlCtxtReset(ctxt);
// //                    }
// //                }
// //
// //                if (lint->appOptions & XML_LINT_SAX_ENABLED) {
// //                    testSAX(lint, filename);
// //                } else {
// //                    parseAndPrintFile(lint, filename);
// //                }
// //            }
// //
// //            xmlFreeParserCtxt(ctxt);
// //        }
// //
// //        if ((lint->appOptions & XML_LINT_TIMINGS) && (lint->repeat > 1)) {
// //            endTimer(lint, "%d iterations", lint->repeat);
// //        }
// //
// //        files += 1;
// //
// //#if HAVE_DECL_MMAP
// //        if (lint->appOptions & XML_LINT_MEMORY) {
// //            munmap(lint->memoryData, lint->memorySize);
// //            close(memoryFd);
// //        }
// //#endif
// //    }
// //
// //    if (lint->appOptions & XML_LINT_GENERATE)
// //	parseAndPrintFile(lint, NULL);
// //
// //    if ((files == 0) && ((lint->appOptions & XML_LINT_GENERATE) != XML_LINT_GENERATE) && (lint->version == 0)) {
// //	usage(errStream, argv[0]);
// //        lint->progresult = XMLLINT_ERR_UNCLASS;
// //    }
// //
// //error:
// //
// //#ifdef LIBXML_SCHEMATRON_ENABLED
// //    if (lint->wxschematron != NULL)
// //	xmlSchematronFree(lint->wxschematron);
// //#endif
// //#ifdef LIBXML_RELAXNG_ENABLED
// //    if (lint->relaxngschemas != NULL)
// //	xmlRelaxNGFree(lint->relaxngschemas);
// //#endif
// //#ifdef LIBXML_SCHEMAS_ENABLED
// //    if (lint->wxschemas != NULL)
// //	xmlSchemaFree(lint->wxschemas);
// //#endif
// //#if defined(LIBXML_READER_ENABLED) && defined(LIBXML_PATTERN_ENABLED)
// //    if (lint->patternc != NULL)
// //        xmlFreePattern(lint->patternc);
// //#endif
// //
// //    xmlCleanupParser();
// //
// //    if ((lint->maxmem) && (xmllintMaxmemReached)) {
// //        fprintf(errStream, "Maximum memory exceeded (%d bytes)\n",
// //                xmllintMaxmem);
// //    } else if (lint->progresult == XMLLINT_ERR_MEM) {
// //        fprintf(errStream, "Out-of-memory error reported\n");
// //    }
// //
// //#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
// //    if ((lint->maxmem) &&
// //        (xmllintOom != (lint->progresult == XMLLINT_ERR_MEM))) {
// //        fprintf(stderr, "xmllint: malloc failure %s reported\n",
// //                xmllintOom ? "not" : "erroneously");
// //        abort();
// //    }
// //#endif
// //
// //    return(lint->progresult);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlCtxtResetPush(xmlParserCtxt * ctxt, const char * chunk, int size, const char * filename, const char * encoding);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Use the project header for the target symbol */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlerror.h"

#ifndef FUZZER_INPUT_CAP
/* Cap how much of the fuzzer input we hand to the API to avoid huge allocations */
#define FUZZER_INPUT_CAP (1 << 16) /* 64 KiB */
#endif

/* Suppress libxml2 error messages to avoid noisy output during fuzzing */
static void ensure_libxml_initialized(void) {
    static int initialized = 0;
    if (initialized) return;
    initialized = 1;
    xmlInitParser();
    /* Disable default error handler (suppress stderr noise) */
    xmlSetGenericErrorFunc(NULL, NULL);
}

/*
 * Fuzzer entrypoint expected by libFuzzer:
 * extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
 */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    ensure_libxml_initialized();

    /* Create a parser context */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        return 0;
    }

    /* Limit the amount of data we pass as the chunk */
    size_t cap = Size;
    if (cap > FUZZER_INPUT_CAP) cap = FUZZER_INPUT_CAP;
    /* Allocate a temporary buffer and null-terminate it for safety when deriving strings */
    char *buf = (char *)malloc(cap + 1);
    if (buf == NULL) {
        xmlFreeParserCtxt(ctxt);
        return 0;
    }
    if (cap > 0) memcpy(buf, Data, cap);
    buf[cap] = '\0';

    /* Compute an int size parameter for xmlCtxtResetPush, safely clamped to INT_MAX */
    int call_size = (int)(cap > (size_t)INT_MAX ? INT_MAX : (int)cap);

    /* Variant A: call with no filename/encoding (common simple case) */
    (void)xmlCtxtResetPush(ctxt, (const char *)buf, call_size, NULL, NULL);

    /* Variant B: derive small filename/encoding strings from input to exercise more code paths */
    char fname[64] = {0};
    char enc[32] = {0};
    int use_fname = 0, use_enc = 0;

    if (Size >= 1) {
        /* Build a short printable pseudo-filename from the first up to 12 bytes */
        size_t fnlen = (cap < 12) ? cap : 12;
        for (size_t i = 0; i < fnlen && i + 1 < sizeof(fname); ++i) {
            unsigned char b = (unsigned char)buf[i];
            /* map to lowercase letters or digits and keep safe chars for filenames */
            char c = (char)('a' + (b % 26));
            fname[i] = c;
        }
        /* append a suffix to look like a filename */
        strncat(fname, ".xml", sizeof(fname) - strlen(fname) - 1);
        use_fname = 1;
    }

    if (Size >= 2) {
        /* Choose an encoding string from a small set based on second byte */
        unsigned char b = (unsigned char)buf[1];
        if ((b & 3) == 0) {
            strncpy(enc, "UTF-8", sizeof(enc) - 1);
        } else if ((b & 3) == 1) {
            strncpy(enc, "ISO-8859-1", sizeof(enc) - 1);
        } else {
            strncpy(enc, "UTF-16", sizeof(enc) - 1);
        }
        use_enc = 1;
    }

    /* Call again with filename and encoding variants to reach additional code paths */
    const char *fnp = use_fname ? fname : NULL;
    const char *encp = use_enc ? enc : NULL;
    (void)xmlCtxtResetPush(ctxt, (const char *)buf, call_size, fnp, encp);

    /* Another call: sometimes pass size 0 to exercise reset behavior with no data */
    (void)xmlCtxtResetPush(ctxt, NULL, 0, NULL, NULL);

    /* Clean up */
    free(buf);
    xmlFreeParserCtxt(ctxt);

    /* Note: xmlCleanupParser() is intentionally not called here. It's expensive and
       may interfere with repeated fuzzing iterations. */

    return 0;
}
