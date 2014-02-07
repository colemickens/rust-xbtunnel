linux:
ifeq ($(OS),Windows_NT)
	(cd ../rust-pcap;   rustc lib.rs -L C:\\WpdPack\\Lib)
	(cd ../rust-packet; rustc lib.rs -L C:\\WpdPack\\Lib)
	rustc main.rs -L ../rust-pcap/ -L ../rust-packet -o xbtunnel.exe -L C:\\WpdPack\\Lib
else
	(cd ../rust-pcap;   rustc lib.rs)
	(cd ../rust-packet; rustc lib.rs)
	rustc main.rs -L ../rust-pcap/ -L ../rust-packet -o xbtunnel
endif

host:
	sudo ./xbtunnel --dev enp3s0 --host

join:
	sudo ./xbtunnel --dev enp3s0 --join 0.0.0.0:8602

# under windows:
#    C:\Users\colemick\TEMP\rust-xbtunnel>"C:\MinGW\msys\1.0\bin\make.exe"
#    (cd ../rust-pcap;   rustc lib.rs -L C:\\WpdPack\\Lib)
#    error: couldn't read lib.rs -L C:\WpdPack\Lib: no such file or directory
#    make.exe": *** [linux] Error 101

# looks like it's treating "lib.rs -L C:\WpdPack\Lib" as a single argument... not sure why.
