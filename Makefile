all: Main.c symmetric.c asymmetric.c hash.c signature.c
	gcc -o cryptogator main.c symmetric.c asymmetric.c hash.c signature.c -lgcrypt -lgpg-error