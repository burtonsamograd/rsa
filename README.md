rsa - The RSA Encryption Algorithm in Common Lisp
-------------------------------------------------

Encrypt and decrypt messages using a key and the beauty of mathematics.

--

First, get a Common Lisp implementation and install it:

    http://sbcl.org

Run your lisp:

    $ ./sbcl

Load this file:

    (load "rsa.lisp")

Generate a key:

    (setq *key* (rsa-gen-key "me"))

Encrypt:

    (setq *cyphertext* (rsa-encrypt-text *key* "this is a test"))

Decrypt:

    (setq *plaintext* (rsa-decrypt-text *key* *cyphertext*))

There is also a basic key management db.

List keys:

    (rsa-list-keys)

Find a key by name:

    (rsa-find-key name)

Bonus
-----

You will also find a fast, self contained impmentation of the Miller
Rabkin primality test.

--
Burton Samograd
burton.samograd@gmail.com
2016