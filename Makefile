all:
	(cd ../pcapfe; rustc lib.rs)
	(cd ../pktutil; rustc lib.rs)
	rustc main.rs -L ../pcapfe/ -L ../pktutil

host:
	sudo ./tunnelrs --dev enp3s0 --host

join:
	sudo ./tunnelrs --dev enp3s0 --join 0.0.0.0:8602
