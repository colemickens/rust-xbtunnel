all:
ifeq ($(OS),Windows_NT)
	# only works in git bash shell
	#(cd ../rust-pcap;   start /W  rustc lib.rs -L C:\WpdPack\Lib) # same
	#(cd ../rust-packet; start /W  rustc lib.rs -L C:\WpdPack\Lib) # in git bash this exits immediately and races, weird stuff
	rustc main.rs -L ../rust-pcap/ -L ../rust-packet -L C:\\WpdPack\\Lib -o xbtunnel.exe
else
	(cd ../rust-pcap;   rustc lib.rs)
	(cd ../rust-packet; rustc lib.rs)
	rustc main.rs -L ../rust-pcap/ -L ../rust-packet -o xbtunnel
endif

host:
	sudo ./xbtunnel --dev enp3s0 --host

join:
	sudo ./xbtunnel --dev enp3s0 --join 0.0.0.0:8602


host-win:
	xbtunnel.exe --dev \Device\NPF_{91C58076-8489-4BF0-8583-34D1CACEBD31} --host

join-win:
	xbtunnel.exe --dev="\Device\NPF_{91C58076-8489-4BF0-8583-34D1CACEBD31}" --join 64.187.174.96:8602