LIBDIR := lib
include $(LIBDIR)/main.mk

cnote-draft-yasskin-http-origin-signed-responses.html: draft-yasskin-http-origin-signed-responses.html cnote-footer.html
	cat draft-yasskin-http-origin-signed-responses.html cnote-footer.html > $@

$(LIBDIR)/main.mk:
ifneq (,$(shell git submodule status $(LIBDIR) 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone -q --depth 10 $(CLONE_ARGS) \
	    -b master https://github.com/martinthomson/i-d-template $(LIBDIR)
endif
