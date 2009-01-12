mod_log_slow.la: mod_log_slow.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_log_slow.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_log_slow.la
