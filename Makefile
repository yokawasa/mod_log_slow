##
##  Makefile -- Build procedure for sample log_slow Apache module
##  Autogenerated via ``apxs -n log_slow -g''.
##

ap_basedir=/home/apache-2.2.2
builddir=.
top_srcdir=$(ap_basedir)
top_builddir=$(ap_basedir)
include $(ap_basedir)/build/special.mk

#   the used tools
APXS=$(ap_basedir)/bin/apxs
APACHECTL=$(ap_basedir)/bin/apachectl

#   the default target
all: local-shared-build

#   install the shared object file into Apache 
install: install-modules-yes

#   cleanup
clean:
	-rm -f mod_log_slow.o mod_log_slow.lo mod_log_slow.slo mod_log_slow.la 

#   simple test
test: reload
	lynx -mime_header http://localhost/log_slow

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop
