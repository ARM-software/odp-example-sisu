################################################################################
# Copyright 2015, ARM Limited or its affiliates. All rights reserved.
################################################################################

#Name of directory
DIRNAME = sisu
#List of executable files to build
TARGETS = sisu controller
#List object files for each target
OBJECTS_sisu = \
ppp_graph.o \
ppp_edge.o \
ppp_module.o \
ppp_packet.o \
ppp_if.o \
pkt_hdrs.o \
lpm.o \
capif.o \
odp_src.o \
odp_sink.o \
sisu.o \
main.o \
cpagent.o \
gtpu.o \
ipv4.o \
ethernet.o \
tgen.o \
tterm.o \
accounting.o \
debug.o \
comms.o

OBJECTS_controller = \
controller.o \
comms.o

ifneq ($(no-ipsec),yes)
OBJECTS_sisu += ipsec.o
OBJECTS_sisu += sad.o
OBJECTS_sisu += spd.o
OBJECTS_sisu += replayprot.o
endif

#Customizable compiler and linker flags
GCCTARGET =
ifneq ($(DEBUG),yes)
DEFINE += -DNDEBUG#disable assertion
endif
ifeq ($(sisu-acc),yes)
DEFINE += -DSISU_ACCOUNTING
DEFINE += -DACCOUNTING
endif
ifeq ($(sisu-dbg),yes)
DEFINE += -DSISU_DEBUG
endif
ifeq ($(no-ipsec),yes)
DEFINE += -DNO_IPSEC
endif
ifeq ($(end-to-end),yes)
DEFINE += -DENDTOEND
endif
DEFINE += -DPREFETCH
#DEFINE += -DACCOUNTING#per-packet cycle accounting
DEFINE += -DCACHE_LINE_SIZE=64
CCFLAGS += -g -ggdb -Wall
ifneq ($(DEBUG),yes)
CCFLAGS += -O2
endif
CXXFLAGS += -fno-exceptions -std=c++98
LDFLAGS += -g -ggdb -fno-exceptions
#ODP and dependent libraries

ODP_LIB = $(shell pkg-config --libs libodp-linux)
ODPHELPER_LIB = $(shell pkg-config --libs libodphelper-linux)

ODP_INCLUDEDIR = $(shell pkg-config --variable=includedir libodp-linux)
ODPHELPER_INCLUDEDIR = $(shell pkg-config --variable=includedir libodphelper-linux)

CCFLAGS  += -I$(ODP_INCLUDEDIR) -I$(ODPHELPER_INCLUDEDIR)
LDFLAGS += $(ODP_LIB) $(ODPHELPER_LIB)

LIBS += -L/usr/local/lib -pthread -lrt
LIBS += -lpcap
ifeq ($(PGO),instrument)
$(warning PGO=$(PGO))
CCFLAGS += -fprofile-generate
LIBS += -lgcov
else ifeq ($(PGO),optimize)
$(warning PGO=$(PGO))
CCFLAGS += -fprofile-use
endif 
#CCFLAGS += -finstrument-functions -pg
#LDFLAGS += -finstrument-functions -pg

#Where to find the source files
VPATH += .

#Default to non-verbose mode (echo command lines)
VERB = @

#Location of object and other derived/temporary files
OBJDIR = obj#Must not be .

###############################################################################
# Make actions (phony targets)
################################################################################

.PHONY : default all clean tags etags

default:
	@echo "Make targets:"
	@echo "all         build all targets ($(TARGETS))"
	@echo "clean       remove derived files"
	@echo "tags        generate vi tags file"
	@echo "etags       generate emacs tags file"

all : $(TARGETS)

#Make sure we don't remove current directory with all source files
ifeq ($(OBJDIR),.)
$(error invalid OBJDIR=$(OBJDIR))
endif
ifeq ($(TARGETS),.)
$(error invalid TARGETS=$(TARGETS))
endif
clean:
	@echo "--- Removing derived files"
	$(VERB)-rm -rf $(OBJDIR) $(TARGETS) tags TAGS perf.data perf.data.old *.pcap

tags :
	$(VERB)ctags -R .

etags :
	$(VERB)ctags -e -R .

################################################################################
# Setup tool commands and flags
################################################################################

#Defaults to be overriden by compiler makefragment
CCOUT = -o $@
ASOUT = -o $@
LDOUT = -o $@

ifneq ($(GCCTARGET),)
#Some experimental cross compiling support
#GCCROOT = /opt/gcc-linaro-arm-linux-gnueabihf-4.7-2013.02-01-20130221_linux
#GCCLIB = $(GCCROOT)/lib/gcc/$(GCCTARGET)/4.7.3
GCCROOT = /opt/gcc-linaro-arm-linux-gnueabihf-4.7-2012.12-20121214_linux
GCCSETUP = PATH=$(GCCROOT)/bin:$(GCCROOT)/$(GCCTARGET)/bin:/bin:/usr/bin
CC = $(GCCSETUP) $(GCCROOT)/bin/$(GCCTARGET)-gcc
CXX = $(GCCSETUP) $(GCCROOT)/bin/$(GCCTARGET)-g++
LD = $(GCCSETUP) $(GCCROOT)/bin/$(GCCTARGET)-g++
else
#Native compilation
ifeq ($(CLANG),yes)
CC = clang
CXX = clang++
AS = as
LD = clang++
else
CC = gcc
CXX = g++
AS = as
LD = g++
endif
endif
BIN2C = ./bin2c

#Important compilation flags
CCFLAGS += -c -MMD -MP

################################################################################
# Post-process some variables and definitions, generate dependencies
################################################################################

CCFLAGS += $(DEFINE) $(INCLUDE)
#Generate list of all object files (for all targets)
override OBJECTS := $(addprefix $(OBJDIR)/,$(foreach var,$(TARGETS),$(OBJECTS_$(var))))
#Generate target:objects dependencies for all targets
$(foreach target,$(TARGETS),$(eval $(target) : $$(addprefix $$(OBJDIR)/,$$(OBJECTS_$(target)))))
#Special dependency for object files on object directory
$(OBJECTS) : | $(OBJDIR)

################################################################################
# Build recipes
################################################################################

$(OBJDIR) :
	$(VERB)mkdir -p $(OBJDIR)

#Keep intermediate pcap C-files
.PRECIOUS : $(OBJDIR)/%_pcap.c

$(OBJDIR)/%_pcap.o : $(OBJDIR)/%_pcap.c
	@echo "--- Compiling $<"
	$(VERB)$(CC) $(CCFLAGS) $(CCOUT) $<

$(OBJDIR)/%_pcap.c : %.pcap $(BIN2C)
	@echo "--- Generating $@"
	$(VERB)$(BIN2C) -n $(notdir $(basename $@)) -o $@ $<

$(OBJDIR)/%.o : %.cc
	@echo "--- Compiling $<"
	$(VERB)$(CXX) $(CXXFLAGS) $(CCFLAGS) $(CCOUT) $<

$(OBJDIR)/%.o : modules/%.cc
	@echo "--- Compiling $<"
	$(VERB)$(CXX) $(CXXFLAGS) $(CCFLAGS) $(CCOUT) $<

$(OBJDIR)/%.o : lib/%.cc
	@echo "--- Compiling $<"
	$(VERB)$(CXX) $(CXXFLAGS) $(CCFLAGS) $(CCOUT) $<

$(OBJDIR)/%.o : controller_app/%.cc
	@echo "--- Compiling $<"
	$(VERB)$(CXX) $(CXXFLAGS) $(CCFLAGS) $(CCOUT) $<

$(OBJDIR)/%.o : agent/%.cc
	@echo "--- Compiling $<"
	$(VERB)$(CXX) $(CXXFLAGS) $(CCFLAGS) $(CCOUT) $<

$(OBJDIR)/%.o : modules/structures/%.cc
	@echo "--- Compiling $<"
	$(VERB)$(CXX) $(CXXFLAGS) $(CCFLAGS) $(CCOUT) $<

$(OBJDIR)/%.o : graphs/%.cc
	@echo "--- Compiling $<"
	$(VERB)$(CXX) $(CXXFLAGS) $(CCFLAGS) $(CCOUT) $<

$(OBJDIR)/%.o : ppp/%.cc
	@echo "--- Compiling $<"
	$(VERB)$(CXX) $(CXXFLAGS) $(CCFLAGS) $(CCOUT) $<

$(OBJDIR)/%.o : instr/%.cc
	@echo "--- Compiling $<"
	$(VERB)$(CXX) $(CXXFLAGS) $(CCFLAGS) $(CCOUT) $<

$(OBJDIR)/%.o : %.c
	@echo "--- Compiling $<"
	$(VERB)$(CC) $(CCFLAGS) $(CCOUT) $<

$(OBJDIR)/%.o : %.s
	@echo "--- Compiling $<"
	$(VERB)$(AS) $(ASFLAGS) $(ASONLYFLAGS) $(ASOUT) $<

$(OBJDIR)/%.o : %.S
	@echo "--- Compiling $<"
	$(VERB)$(CC) $(CCFLAGS) $(addprefix $(ASPREFIX),$(ASFLAGS)) $(CCOUT) $<

$(TARGETS) :
	@echo "--- Linking $@ from $(OBJECTS_$@)"
	$(VERB)$(LD) $(LDFLAGS) $(LDOUT) $(addprefix $(OBJDIR)/,$(OBJECTS_$@)) $(GROUPSTART) $(LIBS) $(GROUPEND) $(LDMAP)

################################################################################
# Include generated dependencies
################################################################################

-include $(patsubst %.o,%.d,$(OBJECTS))
# DO NOT DELETE
