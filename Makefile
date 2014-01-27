all:
	(cd ../pktutil; rustpkg build;)
	(cd ../pcapfe; rustpkg build;)
	rustc main.rs \
		-L ../pcapfe/.rust/build/x86_64-unknown-linux-gnu/pcapfe/ \
		-L ../pktutil/.rust/build/x86_64-unknown-linux-gnu/pktutil/

host:
	sudo ./tunnelrs --dev enp3s0 --host

join:
	sudo ./tunnelrs --dev enp3s0 --join 0.0.0.0:8602