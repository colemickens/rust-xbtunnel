all:
	(cd ../rust-pcap;   rustc lib.rs)
	(cd ../rust-packet; rustc lib.rs)
	rustc main.rs -L ../rust-pcap/ -L ../rust-packet -o xbtunnel

host:
	sudo ./xbtunnel --dev enp3s0 --host

join:
	sudo ./xbtunnel --dev enp3s0 --join 0.0.0.0:8602
