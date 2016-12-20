rsa - The RSA Encryption Algorithm in Common Lisp
-------------------------------------------------

Encrypt and decrypt messages using a key and the beauty of mathematics.

This library does not solve the key exchange problem.

--

First, get a Common Lisp implementation and install it:

    http://sbcl.org

Run your lisp:

    $ ./sbcl

Load this file:

    (load "rsa.lisp")

Generate a key:

    (defparameter *key* (rsa-gen-key "me"))

Encrypt:

    (defparameter *cyphertext* (rsa-encrypt-text *key* "this is a test"))

Decrypt:

    (defparameter *plaintext* (rsa-decrypt-text *key* *cyphertext*))

There is also a basic key management db.

List keys:

    (rsa-list-keys)

Find a key by name:

    (rsa-find-key name)

Load a key into the db:

    (rsa-load-key "me.rsa")

Save a key to a file:

    (rsa-save-key *key* "me.rsa")

Bonus
-----

You will also find a fast, self contained impmentation of the Miller
Rabkin primality test.

TODO
----

-- load and save keys

    (rsa-save-key "filename")
    (rsa-load-key "filename")

--
Burton Samograd
burton.samograd@gmail.com
2016