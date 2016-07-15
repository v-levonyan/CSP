# CSP 1.0.0
Cryptographic Service Provider

DESCRIPTION
-----------

The CSP project is a client server command line application, for general purpose software cryptographic services. CSP was implemented in C and python, and uses secure socket layer(SSL) protocol. It's the first version of the project.

OVERVIEW
--------

The CSP toolkit currently includes:

  - Hash functions (SHA1, ... ).                                                                                                    
  - Private key generation(for DES, 3DES, AES128, AES192, AES256).                                                                    
  - Private key encryption/decryption(AES128, AES192, AES256).                                                                          

The project currently being expanded, and in near times it'll include new features. The following ara some of the feature that will be added to the product:

 -  Public key cryptography.                                                                                                          
 -  Eliptic key cryptography.                                                                                                         
 -  Certificates generation.                                                                                                            

INSTALLATION
------------

The project is platform-dependent, it works only on linux platforms. Installation is quite straightforward. In order to install the 
application you should have installed a few tools:

    Scons http://scons.org/                                                                                                           
    OpenSSL https://www.openssl.org/                                                                                                  
    Sqlite https://www.sqlite.org/index.html                                                                                          
    Python https://www.python.org/                                                                                                    

In order to install CSP:
.Clone the git repository on your machine.                                                                                           
.Change directory to the CSP directory                                                                                                
.Type scons on your shell and run.                                                                                                   

If you wish to report a bug then please report to the following mail:
david.tsaturyan.95@gmail.com
