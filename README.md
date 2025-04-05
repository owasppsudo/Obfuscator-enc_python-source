the best encrypter and obfuscator python script 100% safe 

features:

Multi-stage encryption with various algorithms:
Instead of just AES and Fernet, I also use ChaCha20 and RSA.

Multi-layer compression and encoding:
I add more layers of compression and encoding (such as bzip2, base91, and ROT13).

Ultra-complex obfuscation:
I use multiple stages of obfuscation with AST, heavy injection of fake code, restructuring the code, and converting it into unreadable formats.

Injection of anti-debugging mechanisms:
I add code that causes the program to crash if someone tries to debug it.

Using a simple VM:
I create a very basic virtual machine within the code to execute the main code.

Encryption:
ChaCha20 + AES-256-GCM + RSA-4096 + Fernet in a chained sequence.
A 64-byte key with SHA3-512 and 1 million iterations.

Compression:
Addition of bz2 to the compression chain.

Encoding:
Using base91 instead of Base85 for greater compression and complexity.

Obfuscation:
Variables changed to random 30-character names.
15 lines of heavy fake code injected.
The code is encoded to Base91, then Hex, and mixed with random noise.
A simple VM added to execute the final code.

Anti-debugging:
Checking sys.gettrace to detect a debugger.
Checking execution time to detect debugging pauses.


Usage:

1.Run the script. 
 git clone https://github.com/owasppsudo/Obfuscator-enc_python-source 

 cd Obfuscator-enc_python-source
 python3 Main.py
2.Enter the full path to the file, for example: C:/Users/YourName/test.py 

3.Enter the password. 

4.The output file (for example C:/Users/YourName/test_noobhackerenc.py) will be saved in the same directory.


