# Gangite

Gangite is a Ganglia/Graphite bridge - translating metrics from Ganglia's gmond to Graphite's carbon.

To use, just configure it with the address of the gmond and carbon daemons:

    gangite -g gmond.example.com:8649 -c carbon.example.com:2023

by default the addresses of localhost:8649 and localhost:2023 are used.

After connecting to the services, gangite will check for statistics every 10
seconds. This can be changed with the -p argument.

gangite used the expat streaming XML library, and therefore has low CPU
utilization. But you should probably use the builtin [Graphite/Carbon
integration](https://github.com/ganglia/monitor-core/wiki/Ganglia-Graphite).
