# Raw Dns Query
This is a simple program sending dns query to an specifed server.

## Feutures
- Recursive dns query
- Iterative dns query
- Finding type A records of all host names in a single CSV file

# How it works
- Recursive dns query
```sh
python main.py <host name> <dns server> 1
```

- Iterative dns query
```sh
python main.py <host name> <dns server> 0
```

- Finding type A records

Note:  This uses recursive dns to find the IPv4 of the host names
```sh
python main.py csv <dns server>
```