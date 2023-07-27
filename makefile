# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------
#  Layout
LIB_DIR := library
SRC_DIR := source
INC_DIR := include
OUT_DIR := output

#  Program
MKDIR := mkdir -p
WGET := wget
RM := rm -f
MV := mv
CC := gcc
TEST := test
SORT := sort
GREP := grep
AWK := awk
PR := pr
SED := sed
LN := ln -s
CAT := cat
TOUCH := touch
BEAR := bear
GIT := git

# Build
DEPFILE := dependency.mk

SOURCES :=
OBJECTS :=
OUTPUT ?= program

DEPENDENCIES :=
LIBRARIES := $(file < $(DEPFILE))

# Internal
.DEFAULT_GOAL = help

# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------
# $(call get-library-name,library-list) -> library-dir-list
get-library-dir = $(addprefix $(LIB_DIR)/,$1)

# $(call get-library-file,library-list) -> library-file-list
get-library-file = $(addsuffix .a,$(addprefix $(OUT_DIR)/$(LIB_DIR)/,$1))

# $(call get-library-source,library-dir) -> source-list
get-library-source = $(subst $(LIB_DIR)/$1/$(SRC_DIR)/main.c,,$(wildcard $(LIB_DIR)/$1/$(SRC_DIR)/*.c))

# $(call source-to-object,source-list) -> object-list
source-to-object = $(addprefix $(OUT_DIR)/,$(patsubst %.c,%.o,$1))

# $(call get-include-path,from-source) -> include-path
get-include-path = $(patsubst %$(SRC_DIR)/,%$(INC_DIR)/,$(dir $1))

# $(call create-symlink,base-dir,target-dir,name)
create-symlink = $(shell												\
	mkdir -p $1;														\
	test -L $(strip $1)/$(strip $3) || 									\
	ln -s $$(realpath -m --relative-to $1 $2) $(strip $1)/$(strip $3)	\
)

# $(call create-include-dir,base-dir)
create-include-dir = $(foreach d,$(file < $1/$(DEPFILE)),					\
	$(call create-symlink,													\
		$(patsubst %/,%,$1/$(INC_DIR)/$(dir $d)),							\
		$(LIB_DIR)/$d/$(INC_DIR),											\
		$(notdir $d)														\
	)																		\
)

# $(call get-number-of-libraries)
get-number-of-libraries = $(words 											\
	$(foreach u,$(wildcard $(LIB_DIR)/*),$(wildcard $u/*))					\
)

define make-library
$(eval LIB_SRC := $(call get-library-source,$2))
$(eval LIB_OBJ := $(call source-to-object,$(LIB_SRC)))

LIBRARIES += $2

SOURCES += $(LIB_SRC)
OBJECTS += $(LIB_OBJ)

$(call get-library-file,$2): $(LIB_OBJ)
	$(AR) $(ARFLAGS) $$@ $$^

endef

# $(call make-program,name,libraries)
define make-program
$(eval SRC := $(wildcard $(SRC_DIR)/*.c))
$(eval OBJ := $(call source-to-object,$(SRC)))

SOURCES += $(SRC)
OBJECTS += $(OBJ)

OUTPUT := $1

$(OUT_DIR)/$1: $(OBJ) $(call get-library-file,$2)
	$(CC) -o $$@ $$? 

endef
# -----------------------------------------------------------------------------
# Preprocessing
# -----------------------------------------------------------------------------
$(call create-include-dir,.)

$(foreach l,$(LIBRARIES),													\
	$(eval LIBRARIES += $(file < $(LIB_DIR)/$l/$(DEPFILE)))					\
)

ifneq "$(words $(LIBRARIES))" "$(call get-number-of-libraries)"

download_libraries := $(foreach l,$(LIBRARIES),								\
	$(shell test -d $(LIB_DIR)/$l 											\
		 || git clone https://github.com/$l $(LIB_DIR)/$l)					\
	$(call create-include-dir,$(LIB_DIR)/$l)								\
)

.PHONY: FORCE
FORCE:

%:: FORCE
	@$(MAKE) $@

else

create_output_dir := $(shell												\
	$(MKDIR) $(OUT_DIR);													\
	$(MKDIR) $(OUT_DIR)/$(SRC_DIR);											\
	for f in $(sort $(dir $(OBJECTS)));										\
	do																		\
		$(TEST) -d $$f 														\
			|| $(MKDIR) $$f;												\
	done;																	\
	for l in $(LIBRARIES);													\
	do																		\
		$(MKDIR) $(OUT_DIR)/$(LIB_DIR)/$$l/$(SRC_DIR);						\
	done																	\
)

$(eval $(call make-program,$(OUTPUT),$(file < $(DEPFILE))))

# -----------------------------------------------------------------------------
# Recipes 
# -----------------------------------------------------------------------------
.SECONDEXPANSION:
$(call get-library-file,$(LIBRARIES)): $(OUT_DIR)/$(LIB_DIR)/%.a: 			\
		$$(call source-to-object,$$(call get-library-source,%))				\
		| $(call get-library-dir,%)
	$(AR) $(ARFLAGS) $@ $^

$(OUT_DIR)/%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@ 								\
		  -I$(call get-include-path,$<)

$(DEPENDENCIES): $(OUT_DIR)/%.d: %.c
	# Create dependency files
	@$(CC) $(CFLAGS) -I$(call get-include-path,$<)							\
		   $(CPPFLAGS) $(TARGET_ARCH) -MG -MM $<	| 						\
	$(SED) 's,\($(notdir $*)\.o\) *:,$(dir $@)\1 $@: ,' > $@.tmp
	@$(MV) $@.tmp $@

# -----------------------------------------------------------------------------
# Commands
# -----------------------------------------------------------------------------
.PHONY: build
build: $(OUT_DIR)/$(OUTPUT)

.PHONY: archive
archive: LIBRARIES += $(OUTPUT)

.PHONY: compile
compile: $(OBJECTS)

.PHONY: help
help:
	@$(CAT) $(MAKEFILE_LIST)											|	\
	$(GREP) -v -e '^$$1'												| 	\
	$(AWK) '/^[^.%][-A-Za-z0-9_]*:/											\
		   { print substr($$1, 1, length($$1) - 1) }'					|	\
	$(SORT)																|	\
	$(PR) --omit-pagination --width=80 --columns=4

.PHONY: all
all: build

.PHONY: clean
clean:
	$(RM) -r $(OUT_DIR)
	$(RM) -r $(addprefix $(INC_DIR)/,$(dir $(LIBRARIES)))

.PHONY: cleanll
cleanall: clean
	$(RM) -r $(LIB_DIR)

.PHONY: variables
variables:
	# Variables: $(strip $(foreach v,$(.VARIABLES),							\
			$(if $(filter file,$(origin $v)),$v))							\
	)
	$(foreach g,$(MAKECMDGOALS),$(if $(filter-out variables,$g),$g: $($g)))

.PHONY: install
install:

.PHONY: run
run:
	@./$(OUT_DIR)/$(OUTPUT)

# -----------------------------------------------------------------------------
# Include
# -----------------------------------------------------------------------------
ifdef $(strip $(filter $(MAKECMDGOALS),"clean" "cleanall"))
include $(DEPENDENCIES)
endif

endif
