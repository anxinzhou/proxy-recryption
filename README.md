# proxy-recryption

A C version base on library [PBC](https://crypto.stanford.edu/pbc/)

A go version with C Wrapper.

# usage

## For C version

1. Install GMP [https://gmplib.org/](https://gmplib.org/), A big number library

2. Install [PBC](https://crypto.stanford.edu/pbc/). A curve and pairing library

3. Under folder C.  

```
make
```

4. Test 

```
./proxy
```

## For Go wrapper

Follow example under folder Go. You can see how to used the compiled `so` and header file to use the c version in GO.

GMP header file is located in `/usr/local/include`. PBC header file is located in `/usr/local/include/pbc`.  `proxy.h` is also required (under this project folder `C/`)



# ! This is only for experiment use.

