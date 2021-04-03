global RelationTable :table[addr] of set[string];

event http_header(c: connection, is_orig: bool, name: string, value: string) {
	local source_ip: addr = c$id$orig_h;
	if (name == "USER-AGENT"){
	local agents: string = to_lower(value);
		if (source_ip in RelationTable) {
			add RelationTable[source_ip][agents];
		} else {
			RelationTable[source_ip] = set(agents);
		}
	}
}

event zeek_done() {
	for (source_ip in RelationTable) {
		if (|RelationTable[source_ip]| >= 3) {
			print fmt("%s is a proxy",source_ip);
		}
	}
}
