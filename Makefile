all:
	rustpkg build tunnelrs

host:
	sudo ./tunnelrs --dev enp3s0 --host

join:
	sudo ./tunnelrs --dev enp3s0 --join 0.0.0.0:8602