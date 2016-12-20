rsa - The RSA Encryption Algorithm in Common Lisp
-------------------------------------------------

Encrypt and decrypt messages using a key and the beauty of mathematics.

This library does not solve the key exchange problem.

--

First, get a Common Lisp implementation and install it:

    http://sbcl.org

Run your lisp:

```sh
    $ ./sbcl
```

Load this file:

```cl
(load "rsa.lisp")
```

Generate a key:

```cl
(defparameter *key* (rsa-gen-key "me"))
```

Encrypt:

```cl
(defparameter *cyphertext* (rsa-encrypt-text *key* "this is a test"))
```

Decrypt:

```cl
(defparameter *plaintext* (rsa-decrypt-text *key* *cyphertext*))
```

There is also a basic key management db.

List keys:

```cl
(rsa-list-keys)
```

Find a key by name:

```cl
(rsa-find-key name)
```

Load a key into the db:

```cl
(rsa-load-key "me.rsa")
```

Save a key to a file:

```cl
(rsa-save-key *key* "me.rsa")
```

Bonus
-----

You will also find a fast, self contained impmentation of the Miller
Rabkin primality test.

TODO
----

- save encrypted message to a file

- load and decrypt a message from a file

--
Burton Samograd
burton.samograd@gmail.com
2016