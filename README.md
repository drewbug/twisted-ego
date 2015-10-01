# twisted-ego

    git submodule update --init

    gcc ed25519-donna/ed25519.c -m64 -O3 -c
    gcc -lcrypto ed25519.o twisted-ego.c -o twisted-ego
    
    ./twisted-ego

    gcc curve25519-donna/curve25519-donna-c64.c -m64 -O3 -c
    gcc -lcrypto curve25519-donna-c64.o twisted-secrets.c -o twisted-secrets
    
    ./twisted-secrets
