PREFIX ?= /usr/local/snort
SNORT = $(PREFIX)/bin/snort

CXXFLAGS += -Wall -Wno-address-of-packed-member -pedantic
CXXFLAGS += -std=c++14 -fPIC -fstack-protector-strong -fno-rtti
CXXFLAGS += -I$(PREFIX)/include/snort

ifdef DEBUG
	CXXFLAGS += -g
else
	CXXFLAGS += -O3
endif

CATEGORIES = $(shell ls *_*.cc | cut -d_ -f1 | uniq)
OBJECTS = $(addsuffix .so, $(CATEGORIES))
LOADER_RULES = $(addsuffix .rules, $(CATEGORIES))
RESULTS = $(addsuffix /results/snort3_alerts.txt, $(wildcard tests/*))

all: build

build: $(OBJECTS) $(LOADER_RULES)

$(OBJECTS):
	$(eval CG=$(subst .so,,$@))
	@./generate_category.sh $(CG) > $(CG).cc
	$(CXX) $(CXXFLAGS) -shared $(CG).cc $(CG)_*.cc -o $@
	@rm $(CG).cc

$(LOADER_RULES): $(OBJECTS)
	$(eval SO=$(subst .rules,.so,$@))
	$(SNORT) --warn-all --plugin-path $(SO) --dump-dynamic-rules > $@

test: build $(RESULTS)

tests/%/results/snort3_alerts.txt: tests/% $(OBJECTS)
	$(SNORT) \
	 -H -q -c $(PREFIX)/etc/snort/snort.lua \
	 --talos --plugin-path . -R $</test.rules \
	 --lua 'ips.enable_builtin_rules = false;' \
	 --lua 'profiler.rules.show = false;' \
	 --lua 'http_inspect.decompress_zip = true;' \
	 --lua 'search_engine.search_method = "ac_full";' \
	 --pcap-dir=$</pcaps/ \
	 > $</results/snort3_alerts.txt; \
	 diff -u $</results/expected $</results/snort3_alerts.txt

clean:
	rm -f *.so *.rules
	find . -type f -name 'snort3_alerts.txt' -delete

.PHONY: all build test clean
