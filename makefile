all: chacha20 

chacha20: chacha20.c 
	gcc -o chacha20 chacha20.c -lgmp

clean:
	rm -f chacha20