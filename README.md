# twisted-ego

    git submodule update --init
    
    gcc ed25519-donna/ed25519.c -m64 -O3 -c
    gcc -lcrypto ed25519.o twisted-ego.c -o twisted-ego
    
    ./twisted-ego
