REM I don't know why this doesn't work in the Makefile with make.exe
REM But it doesn't. I tried. A lot.

cd ..
cd rust-pcap
rustc lib.rs -L C:\\WpdPack\\Lib

REM It just exits here after rustc returns '0'.

cd ..
cd rust-packet
rustc lib.rs -L C:\\WpdPack\\Lib

cd ..
cd rust-xbtunnel
rustc -L ../rust-pcap/ -L ../rust-packet -o xbtunnel.exe -L C:\\WpdPack\\Lib main.rs