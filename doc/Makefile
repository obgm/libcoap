DOXYGEN:=doxygen
DISTDIR?=something
FILES:=Makefile html

doc:	Doxyfile
	$(DOXYGEN) >./doxygen.out 2>&1 

clean:
	@rm -f html

distclean:	clean
	@rm -rf $(DISTDIR)
	@rm -f *~ 

dist:	doc
	cp -r $(FILES) $(DISTDIR)
