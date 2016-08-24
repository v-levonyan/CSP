# CSP 1.0.0
Cryptographic Service Provider

DESCRIPTION
-----------

The CSP project is a client/server command line application, for general purpose software cryptographic services. CSP was implemented in C and python. CSP uses secure socket layer(SSL) protocol.                                                                          
Roughly 115 AES256 key generation per 10 second, and gets back their IDs.                                                             Roughly 33 RSA2048 key pair generation per 10 second,and gets back public one.                                                                                                                                                                                               
                                                                                              

OVERVIEW
--------

The CSP toolkit currently includes:

  - Hash functions (SHA1, ... ).                                                                                                    
  - Private key generation(for DES, 3DES, AES128, AES192, AES256).                                                                    
  - Private key encryption/decryption(AES128, AES192, AES256).                                                                    
  - Public  key encryption/decryption(RSA 2048 ).                                                                                                   
  - Elliptic Curve Diffie Hellman.                                                                                                     
                                                                                                                                     
The project is currently being expanded, and in near time it'll include new features. The followings ara some of the features that will be added to the product:

 -  MACs, Digital signatures.                                                                                                        
 -  Certificates generation.                                                                                                            

INSTALLATION
------------

The project is platform-dependent, this works only on linux platforms. Installation is quite straightforward. In order to install the 
application you should have installed several tools:

    Scons http://scons.org/                                                                                                           
    OpenSSL https://www.openssl.org/                                                                                                  
    Sqlite https://www.sqlite.org/index.html                                                                                          
    Python https://www.python.org/                                                                                                    

In order to install CSP:                                                                                                              
.Clone the git repository on your machine.                                                                                           
.Change directory to the CSP directory                                                                                                
.Type scons on your terminal and run.                                                                                                   
USING                                                                                             
-----
.Change directory to the src directory, and type ./server.out -c server.cfg.                                                        
.Open new terminal, change directory to the python_client directory, and type ./client_main.py                                       
                                                                          
                                                                                                                                      
It is the first version of the product, and currently is being expanded.                                                              
If you wish to report a bug then please report to the following mail:
    david.tsaturyan.95@gmail.com
