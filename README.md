# HTTP_Proxy

Simple HTTP Proxy (does not handle HTTPS traffic)


##Usage

```
python pproxy.py - [option]
Options:

-h, --help                        displays information about executabe
-v, --version                     displays version of program and author
-p, --port [port number]          port number that server will use
-n, --numworker [num_of_workers]  Specifies the number of workers in the thread pool used for handling concurrent HTTP requests (default:10)
-t, --timeout [timeout]           The time (seconds) to wait before give up waiting for response from server
-l, --log [log]                   Logs all the HTTP requests and their corresponding responses under the directory specified by log
```
