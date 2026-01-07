fuzz/oss-fuzz-build.sh


$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlsaxuserparsememory.c fuzz/fuzz.o \
        -o $OUT/xmlsaxuserparsememory\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsedefaultdecl.c fuzz/fuzz.o \
        -o $OUT/xmlparsedefaultdecl\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlnewtextreader.c fuzz/fuzz.o \
        -o $OUT/xmlnewtextreader\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlvalidbuildcontentmodel.c fuzz/fuzz.o \
        -o $OUT/xmlvalidbuildcontentmodel\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlsaxparsefilewithdata.c fuzz/fuzz.o \
        -o $OUT/xmlsaxparsefilewithdata\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlcataloglistxmlresolveuri.c fuzz/fuzz.o \
        -o $OUT/xmlcataloglistxmlresolveuri\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsecontent.c fuzz/fuzz.o \
        -o $OUT/xmlparsecontent\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmladdentity.c fuzz/fuzz.o \
        -o $OUT/xmladdentity\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngparse.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngparse\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlvalidgetpotentialchildren.c fuzz/fuzz.o \
        -o $OUT/xmlvalidgetpotentialchildren\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmllintshellgrep.c fuzz/fuzz.o \
        -o $OUT/xmllintshellgrep\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmltextreadersetup.c fuzz/fuzz.o \
        -o $OUT/xmltextreadersetup\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/utf8toeightbit.c fuzz/fuzz.o \
        -o $OUT/utf8toeightbit\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlsetdeclaredencoding.c fuzz/fuzz.o \
        -o $OUT/xmlsetdeclaredencoding\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseattributetype.c fuzz/fuzz.o \
        -o $OUT/xmlparseattributetype\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlsaxparsefile.c fuzz/fuzz.o \
        -o $OUT/htmlsaxparsefile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsename.c fuzz/fuzz.o \
        -o $OUT/xmlparsename\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathevalexpr.c fuzz/fuzz.o \
        -o $OUT/xmlxpathevalexpr\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlautomatanewcounttrans2.c fuzz/fuzz.o \
        -o $OUT/xmlautomatanewcounttrans2\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathobjectcopy.c fuzz/fuzz.o \
        -o $OUT/xmlxpathobjectcopy\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngloadinclude.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngloadinclude\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathdistinctsorted.c fuzz/fuzz.o \
        -o $OUT/xmlxpathdistinctsorted\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlctxtreadfd.c fuzz/fuzz.o \
        -o $OUT/htmlctxtreadfd\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmllintshellsetcontent.c fuzz/fuzz.o \
        -o $OUT/xmllintshellsetcontent\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsepitarget.c fuzz/fuzz.o \
        -o $OUT/xmlparsepitarget\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlsaxparsedoc.c fuzz/fuzz.o \
        -o $OUT/htmlsaxparsedoc\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlctxtparsedocument.c fuzz/fuzz.o \
        -o $OUT/htmlctxtparsedocument\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlschemacomparepreservecollapsestrings.c fuzz/fuzz.o \
        -o $OUT/xmlschemacomparepreservecollapsestrings\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmluriunescapestring.c fuzz/fuzz.o \
        -o $OUT/xmluriunescapestring\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrecovermemory.c fuzz/fuzz.o \
        -o $OUT/xmlrecovermemory\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlcreateentityparserctxt.c fuzz/fuzz.o \
        -o $OUT/xmlcreateentityparserctxt\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmldocdumpmemoryformat.c fuzz/fuzz.o \
        -o $OUT/htmldocdumpmemoryformat\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlparsedocument.c fuzz/fuzz.o \
        -o $OUT/htmlparsedocument\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathnodesetsort.c fuzz/fuzz.o \
        -o $OUT/xmlxpathnodesetsort\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathcomparevalues.c fuzz/fuzz.o \
        -o $OUT/xmlxpathcomparevalues\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlchecklanguageid.c fuzz/fuzz.o \
        -o $OUT/xmlchecklanguageid\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlc14nexecute.c fuzz/fuzz.o \
        -o $OUT/xmlc14nexecute\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlnewentityinputstream.c fuzz/fuzz.o \
        -o $OUT/xmlnewentityinputstream\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlexpandentitiesinattvalue.c fuzz/fuzz.o \
        -o $OUT/xmlexpandentitiesinattvalue\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngcheckrules.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngcheckrules\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseencodingdecl.c fuzz/fuzz.o \
        -o $OUT/xmlparseencodingdecl\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsepubidliteral.c fuzz/fuzz.o \
        -o $OUT/xmlparsepubidliteral\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlreadio.c fuzz/fuzz.o \
        -o $OUT/htmlreadio\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlsnprintfelementcontent.c fuzz/fuzz.o \
        -o $OUT/xmlsnprintfelementcontent\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlcharencinfunc.c fuzz/fuzz.o \
        -o $OUT/xmlcharencinfunc\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsetextdecl.c fuzz/fuzz.o \
        -o $OUT/xmlparsetextdecl\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmluriescapestr.c fuzz/fuzz.o \
        -o $OUT/xmluriescapestr\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlgetutf8char.c fuzz/fuzz.o \
        -o $OUT/xmlgetutf8char\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlsax2resolveentity.c fuzz/fuzz.o \
        -o $OUT/xmlsax2resolveentity\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlreaddoc.c fuzz/fuzz.o \
        -o $OUT/htmlreaddoc\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlreadfd.c fuzz/fuzz.o \
        -o $OUT/xmlreadfd\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseelementmixedcontentdecl.c fuzz/fuzz.o \
        -o $OUT/xmlparseelementmixedcontentdecl\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparserinputbuffercreateurl.c fuzz/fuzz.o \
        -o $OUT/xmlparserinputbuffercreateurl\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmltextreaderread.c fuzz/fuzz.o \
        -o $OUT/xmltextreaderread\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlstringlengetnodelist.c fuzz/fuzz.o \
        -o $OUT/xmlstringlengetnodelist\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngcheckcombine.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngcheckcombine\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlbuildurisafe.c fuzz/fuzz.o \
        -o $OUT/xmlbuildurisafe\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathstringlengthfunction.c fuzz/fuzz.o \
        -o $OUT/xmlxpathstringlengthfunction\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlparsecontenttype.c fuzz/fuzz.o \
        -o $OUT/htmlparsecontenttype\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlcheckutf8.c fuzz/fuzz.o \
        -o $OUT/xmlcheckutf8\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlnewdocprop.c fuzz/fuzz.o \
        -o $OUT/xmlnewdocprop\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlbufferwritequotedstring.c fuzz/fuzz.o \
        -o $OUT/xmlbufferwritequotedstring\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlschemavalidatefile.c fuzz/fuzz.o \
        -o $OUT/xmlschemavalidatefile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlreadfile.c fuzz/fuzz.o \
        -o $OUT/xmlreadfile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlctxtreadio.c fuzz/fuzz.o \
        -o $OUT/xmlctxtreadio\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsesgmlcatalogpubid.c fuzz/fuzz.o \
        -o $OUT/xmlparsesgmlcatalogpubid\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathstringevalnumber.c fuzz/fuzz.o \
        -o $OUT/xmlxpathstringevalnumber\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlskipblankchars.c fuzz/fuzz.o \
        -o $OUT/xmlskipblankchars\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlschemaparse.c fuzz/fuzz.o \
        -o $OUT/xmlschemaparse\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsexmlcatalogfile.c fuzz/fuzz.o \
        -o $OUT/xmlparsexmlcatalogfile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlctxtreadfile.c fuzz/fuzz.o \
        -o $OUT/xmlctxtreadfile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlnodedumpfileformat.c fuzz/fuzz.o \
        -o $OUT/htmlnodedumpfileformat\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlregexpcompile.c fuzz/fuzz.o \
        -o $OUT/xmlregexpcompile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmllintshellload.c fuzz/fuzz.o \
        -o $OUT/xmllintshellload\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlparsedoc.c fuzz/fuzz.o \
        -o $OUT/htmlparsedoc\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseelementcontentdecl.c fuzz/fuzz.o \
        -o $OUT/xmlparseelementcontentdecl\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlsavefileformat.c fuzz/fuzz.o \
        -o $OUT/htmlsavefileformat\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngparsegrammarcontent.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngparsegrammarcontent\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmllintshellregisternamespace.c fuzz/fuzz.o \
        -o $OUT/xmllintshellregisternamespace\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseextparsedent.c fuzz/fuzz.o \
        -o $OUT/xmlparseextparsedent\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathnumberfunction.c fuzz/fuzz.o \
        -o $OUT/xmlxpathnumberfunction\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsestarttag.c fuzz/fuzz.o \
        -o $OUT/xmlparsestarttag\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmllintmain.c fuzz/fuzz.o libxml2/xmllint.o libxml2/shell.o \
        -o $OUT/xmllintmain\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlregcopyatom.c fuzz/fuzz.o \
        -o $OUT/xmlregcopyatom\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmltextreaderpreservepattern.c fuzz/fuzz.o \
        -o $OUT/xmltextreaderpreservepattern\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsedoctypedecl.c fuzz/fuzz.o \
        -o $OUT/xmlparsedoctypedecl\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsedocument.c fuzz/fuzz.o \
        -o $OUT/xmlparsedocument\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlpatterncompilesafe.c fuzz/fuzz.o \
        -o $OUT/xmlpatterncompilesafe\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlsaxparseentity.c fuzz/fuzz.o \
        -o $OUT/xmlsaxparseentity\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngloadexternalref.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngloadexternalref\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlbyteconsumed.c fuzz/fuzz.o \
        -o $OUT/xmlbyteconsumed\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/__xmloutputbuffercreatefilename.c fuzz/fuzz.o \
        -o $OUT/__xmloutputbuffercreatefilename\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlsaxuserparsefile.c fuzz/fuzz.o \
        -o $OUT/xmlsaxuserparsefile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmloutputbufferwritequotedstring.c fuzz/fuzz.o \
        -o $OUT/xmloutputbufferwritequotedstring\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlutf8strloc.c fuzz/fuzz.o \
        -o $OUT/xmlutf8strloc\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlschemacheckfacet.c fuzz/fuzz.o \
        -o $OUT/xmlschemacheckfacet\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsecdsect.c fuzz/fuzz.o \
        -o $OUT/xmlparsecdsect\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmllintshellrngvalidate.c fuzz/fuzz.o \
        -o $OUT/xmllintshellrngvalidate\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlutf8strsub.c fuzz/fuzz.o \
        -o $OUT/xmlutf8strsub\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlschemavalidatestream.c fuzz/fuzz.o \
        -o $OUT/xmlschemavalidatestream\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlcreatecharencodinghandler.c fuzz/fuzz.o \
        -o $OUT/xmlcreatecharencodinghandler\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseenumerationtype.c fuzz/fuzz.o \
        -o $OUT/xmlparseenumerationtype\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlschemavalatomiclistnode.c fuzz/fuzz.o \
        -o $OUT/xmlschemavalatomiclistnode\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlreadmemory.c fuzz/fuzz.o \
        -o $OUT/htmlreadmemory\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmladdchild.c fuzz/fuzz.o \
        -o $OUT/xmladdchild\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathconcatfunction.c fuzz/fuzz.o \
        -o $OUT/xmlxpathconcatfunction\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlctxtparsedtd.c fuzz/fuzz.o \
        -o $OUT/xmlctxtparsedtd\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlctxtreadmemory.c fuzz/fuzz.o \
        -o $OUT/xmlctxtreadmemory\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathtranslatefunction.c fuzz/fuzz.o \
        -o $OUT/xmlxpathtranslatefunction\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlc14nfixupbaseattr.c fuzz/fuzz.o \
        -o $OUT/xmlc14nfixupbaseattr\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlserializetext.c fuzz/fuzz.o \
        -o $OUT/xmlserializetext\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngattributematch.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngattributematch\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlnodelistgetstringinternal.c fuzz/fuzz.o \
        -o $OUT/xmlnodelistgetstringinternal\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxptreval.c fuzz/fuzz.o \
        -o $OUT/xmlxptreval\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsesystemliteral.c fuzz/fuzz.o \
        -o $OUT/xmlparsesystemliteral\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlbufferaddhead.c fuzz/fuzz.o \
        -o $OUT/xmlbufferaddhead\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrecoverdoc.c fuzz/fuzz.o \
        -o $OUT/xmlrecoverdoc\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmloutputbufferwriteescape.c fuzz/fuzz.o \
        -o $OUT/xmloutputbufferwriteescape\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngparseinterleave.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngparseinterleave\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsecomment.c fuzz/fuzz.o \
        -o $OUT/xmlparsecomment\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsexmldecl.c fuzz/fuzz.o \
        -o $OUT/xmlparsexmldecl\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlc14ndocsave.c fuzz/fuzz.o \
        -o $OUT/xmlc14ndocsave\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmladdattributedecl.c fuzz/fuzz.o \
        -o $OUT/xmladdattributedecl\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmltextreaderreadstring.c fuzz/fuzz.o \
        -o $OUT/xmltextreaderreadstring\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlutf8tohtml.c fuzz/fuzz.o \
        -o $OUT/htmlutf8tohtml\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlsaxparsedoc.c fuzz/fuzz.o \
        -o $OUT/xmlsaxparsedoc\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsebalancedchunkmemoryrecover.c fuzz/fuzz.o \
        -o $OUT/xmlparsebalancedchunkmemoryrecover\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlc14nprocessnode.c fuzz/fuzz.o \
        -o $OUT/xmlc14nprocessnode\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathequalvalues.c fuzz/fuzz.o \
        -o $OUT/xmlxpathequalvalues\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngvalidatedatatype.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngvalidatedatatype\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlescapetext.c fuzz/fuzz.o \
        -o $OUT/xmlescapetext\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsecharref.c fuzz/fuzz.o \
        -o $OUT/xmlparsecharref\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlcreateurlparserctxt.c fuzz/fuzz.o \
        -o $OUT/xmlcreateurlparserctxt\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparserinputgetwindow.c fuzz/fuzz.o \
        -o $OUT/xmlparserinputgetwindow\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlnodeparseattvalue.c fuzz/fuzz.o \
        -o $OUT/xmlnodeparseattvalue\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlsaxparsememorywithdata.c fuzz/fuzz.o \
        -o $OUT/xmlsaxparsememorywithdata\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpatheval.c fuzz/fuzz.o \
        -o $OUT/xmlxpatheval\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlutf8strpos.c fuzz/fuzz.o \
        -o $OUT/xmlutf8strpos\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseelementdecl.c fuzz/fuzz.o \
        -o $OUT/xmlparseelementdecl\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngparseelement.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngparseelement\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlnextchar.c fuzz/fuzz.o \
        -o $OUT/xmlnextchar\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathsubstringfunction.c fuzz/fuzz.o \
        -o $OUT/xmlxpathsubstringfunction\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmluriescape.c fuzz/fuzz.o \
        -o $OUT/xmluriescape\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngcheckchoicedeterminism.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngcheckchoicedeterminism\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlfetchxmlcatalogfile.c fuzz/fuzz.o \
        -o $OUT/xmlfetchxmlcatalogfile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlreadernewfile.c fuzz/fuzz.o \
        -o $OUT/xmlreadernewfile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseversioninfo.c fuzz/fuzz.o \
        -o $OUT/xmlparseversioninfo\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngparseattribute.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngparseattribute\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmldocdump.c fuzz/fuzz.o \
        -o $OUT/htmldocdump\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathctxtcompile.c fuzz/fuzz.o \
        -o $OUT/xmlxpathctxtcompile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlreadio.c fuzz/fuzz.o \
        -o $OUT/xmlreadio\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsecatalogfile.c fuzz/fuzz.o \
        -o $OUT/xmlparsecatalogfile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlcharencoutfunc.c fuzz/fuzz.o \
        -o $OUT/xmlcharencoutfunc\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlcatalogunwrapurn.c fuzz/fuzz.o \
        -o $OUT/xmlcatalogunwrapurn\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseattribute.c fuzz/fuzz.o \
        -o $OUT/xmlparseattribute\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlloadsgmlsupercatalog.c fuzz/fuzz.o \
        -o $OUT/xmlloadsgmlsupercatalog\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxnggetelements.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxnggetelements\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlbuildrelativeurisafe.c fuzz/fuzz.o \
        -o $OUT/xmlbuildrelativeurisafe\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlreadfile.c fuzz/fuzz.o \
        -o $OUT/htmlreadfile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlcurrentchar.c fuzz/fuzz.o \
        -o $OUT/xmlcurrentchar\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlscanname.c fuzz/fuzz.o \
        -o $OUT/xmlscanname\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngisnullable.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngisnullable\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsereference.c fuzz/fuzz.o \
        -o $OUT/xmlparsereference\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseentityvalue.c fuzz/fuzz.o \
        -o $OUT/xmlparseentityvalue\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlreadfd.c fuzz/fuzz.o \
        -o $OUT/htmlreadfd\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlreadmemory.c fuzz/fuzz.o \
        -o $OUT/xmlreadmemory\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmllintresourceloader.c fuzz/fuzz.o \
        -o $OUT/xmllintresourceloader\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlctxtparsecontent.c fuzz/fuzz.o \
        -o $OUT/xmlctxtparsecontent\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsenmtoken.c fuzz/fuzz.o \
        -o $OUT/xmlparsenmtoken\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmltextreaderreadinnerxml.c fuzz/fuzz.o \
        -o $OUT/xmltextreaderreadinnerxml\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/streamfile.c fuzz/fuzz.o \
        -o $OUT/streamfile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlsax2entitydecl.c fuzz/fuzz.o \
        -o $OUT/xmlsax2entitydecl\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsedoc.c fuzz/fuzz.o \
        -o $OUT/xmlparsedoc\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsememory.c fuzz/fuzz.o \
        -o $OUT/xmlparsememory\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlsetmetaencoding.c fuzz/fuzz.o \
        -o $OUT/htmlsetmetaencoding\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsexmlcatalogonenode.c fuzz/fuzz.o \
        -o $OUT/xmlparsexmlcatalogonenode\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlencodeentities.c fuzz/fuzz.o \
        -o $OUT/htmlencodeentities\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlreplacenode.c fuzz/fuzz.o \
        -o $OUT/xmlreplacenode\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseencname.c fuzz/fuzz.o \
        -o $OUT/xmlparseencname\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlctxtreadmemory.c fuzz/fuzz.o \
        -o $OUT/htmlctxtreadmemory\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlctxtreadfd.c fuzz/fuzz.o \
        -o $OUT/xmlctxtreadfd\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmldumpelementtable.c fuzz/fuzz.o \
        -o $OUT/xmldumpelementtable\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlloadacatalog.c fuzz/fuzz.o \
        -o $OUT/xmlloadacatalog\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsepi.c fuzz/fuzz.o \
        -o $OUT/xmlparsepi\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathparsencname.c fuzz/fuzz.o \
        -o $OUT/xmlxpathparsencname\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmltextreaderlocatorbaseuri.c fuzz/fuzz.o \
        -o $OUT/xmltextreaderlocatorbaseuri\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseinnodecontext.c fuzz/fuzz.o \
        -o $OUT/xmlparseinnodecontext\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlctxtreadio.c fuzz/fuzz.o \
        -o $OUT/htmlctxtreadio\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngcompile.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngcompile\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlloadcatalogs.c fuzz/fuzz.o \
        -o $OUT/xmlloadcatalogs\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlreaderformemory.c fuzz/fuzz.o \
        -o $OUT/xmlreaderformemory\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlctxtreaddoc.c fuzz/fuzz.o \
        -o $OUT/xmlctxtreaddoc\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/parsexml.c fuzz/fuzz.o \
        -o $OUT/parsexml\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsenotationdecl.c fuzz/fuzz.o \
        -o $OUT/xmlparsenotationdecl\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmladdxmlcatalog.c fuzz/fuzz.o \
        -o $OUT/xmladdxmlcatalog\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngcheckgroupattrs.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngcheckgroupattrs\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsenotationtype.c fuzz/fuzz.o \
        -o $OUT/xmlparsenotationtype\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseexternalentity.c fuzz/fuzz.o \
        -o $OUT/xmlparseexternalentity\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlctxtreaddoc.c fuzz/fuzz.o \
        -o $OUT/htmlctxtreaddoc\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxngiscompilable.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxngiscompilable\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlreaddoc.c fuzz/fuzz.o \
        -o $OUT/xmlreaddoc\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlfreenode.c fuzz/fuzz.o \
        -o $OUT/xmlfreenode\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmldomwrapclonenode.c fuzz/fuzz.o \
        -o $OUT/xmldomwrapclonenode\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlioparsedtd.c fuzz/fuzz.o \
        -o $OUT/xmlioparsedtd\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparsectxtexternalentity.c fuzz/fuzz.o \
        -o $OUT/xmlparsectxtexternalentity\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlinputsetencodinghandler.c fuzz/fuzz.o \
        -o $OUT/xmlinputsetencodinghandler\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlrelaxreadmemory.c fuzz/fuzz.o \
        -o $OUT/xmlrelaxreadmemory\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlstaticcopynode.c fuzz/fuzz.o \
        -o $OUT/xmlstaticcopynode\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlxpathorderdocelems.c fuzz/fuzz.o \
        -o $OUT/xmlxpathorderdocelems\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmldumpxmlcatalognode.c fuzz/fuzz.o \
        -o $OUT/xmldumpxmlcatalognode\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlctxtparsedocument.c fuzz/fuzz.o \
        -o $OUT/xmlctxtparsedocument\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlctxtparsecontentinternal.c fuzz/fuzz.o \
        -o $OUT/htmlctxtparsecontentinternal\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlsax2externalsubset.c fuzz/fuzz.o \
        -o $OUT/xmlsax2externalsubset\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmladdelementdecl.c fuzz/fuzz.o \
        -o $OUT/xmladdelementdecl\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlformaterror.c fuzz/fuzz.o \
        -o $OUT/xmlformaterror\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/htmlparsechunk.c fuzz/fuzz.o \
        -o $OUT/htmlparsechunk\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlsaveuri.c fuzz/fuzz.o \
        -o $OUT/xmlsaveuri\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

$CC $CXXFLAGS \
        $SRC/all_harnesses/xmlparseurisafe.c fuzz/fuzz.o \
        -o $OUT/xmlparseurisafe\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic

# preparing seeds for regression tests

mkdir -p /tmp/corpus && \
    echo "Q0FUQUxPRw0iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi9PVg0NDQ3dQQ==" | base64 -d > /tmp/corpus/catalog1.xml && \
    echo "bGFuZyhvKSsqLWRlK0lzQXIAAAAncHtJc0FybWVuaWFufSoqKyoqKg==" | base64 -d > /tmp/corpus/catalog2.xml 