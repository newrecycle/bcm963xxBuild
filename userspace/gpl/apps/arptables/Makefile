#***********************************************************************
#
#  Copyright (c) 2012  Broadcom Corporation
#  All Rights Reserved
#
#***********************************************************************/

all dynamic install: conditional_build


#
# Set our CommEngine directory (by splitting the pwd into two words
# at /userspace and taking the first word only).
# Then include the common defines under CommEngine.
# You do not need to modify this part.
#
CURR_DIR := $(shell pwd)
BUILD_DIR:=$(subst /userspace, /userspace,$(CURR_DIR))
BUILD_DIR:=$(word 1, $(BUILD_DIR))

include $(BUILD_DIR)/make.common

APP = arptables-v0.0.4
APP_BASE = arptables

.PHONY: check_untar_patch_configure conditional_build check_versions

ifneq ($(strip $(BUILD_ARPTABLES)),)



conditional_build:
	echo "Untarring original $(APP) source"; \
	tar zxvf $(APP).tar.gz 2> /dev/null ; \
	if [ -e $(APP).patch ]; then \
	    echo "Applying patches to $(APP)"; \
	    patch -p1 -b -N -s -d$(APP) < $(APP).patch ; \
	fi; \
	cd $(APP); \
	$(MAKE) -j1; \
	$(MAKE) -j1 install; \
	echo "Done building $(APP_BASE)"
else
conditional_build:
	@echo "skipping $(APP) (not configured)"
endif

# NOTE: make clean from within app does not do a proper job, so wiping out
# entire directory to ensure consistency.
clean:
	rm -rf $(APP)

# The next line is a hint to our release scripts
# GLOBAL_RELEASE_SCRIPT_CALL_DISTCLEAN
distclean: clean



