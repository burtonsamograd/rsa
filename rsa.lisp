;;; -*- Mode: LISP; Syntax: COMMON-LISP; Package: CL-USER; Base: 10 -*-

;;; Copyright (c) 2016-2017  All rights reserved.
;;; Burton Samograd burton.samograd@gmail.com 2016
;;; Ladislav Kosco laci.kosco@gmail.com 2017 

;;; Redistribution and use in source and binary forms, with or without
;;; modification, are permitted provided that the following conditions
;;; are met:

;;;   * Redistributions of source code must retain the above copyright
;;;     notice, this list of conditions and the following disclaimer.

;;;   * Redistributions in binary form must reproduce the above
;;;     copyright notice, this list of conditions and the following
;;;     disclaimer in the documentation and/or other materials
;;;     provided with the distribution.

;;; THIS SOFTWARE IS PROVIDED BY THE AUTHOR 'AS IS' AND ANY EXPRESSED
;;; OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;;; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;;; ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
;;; DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
;;; GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
;;; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
;;; WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

;;
;; rsa.lisp - THe RSA Encryption Algorithm in Common Lisp
;;
(let ((*standard-output* (make-broadcast-stream)))
#+quicklisp (ql:quickload '(:cl-base64 :ironclad :flexi-streams))
;if not quicklisp, use asdf
#-quicklisp (asdf:oos 'asdf:load-op 'ironclad) ;; used for sha256
#-quicklisp (asdf:oos 'asdf:load-op 'cl-base64)
#-quicklisp (asdf:oos 'asdf:load-op 'flexi-streams)
)

(defconstant +E+ 17)

(defun expt-mod (n exponent modulus)
  "As (mod (expt n exponent) modulus), but more efficient. From Cliki"
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
	   (integer n exponent modulus)
	   #+sbcl (sb-ext:muffle-conditions sb-ext:compiler-note) ; too many optimization notes here
	   ) 
  (loop with result = 1
     for i of-type fixnum from 0 below (integer-length exponent)
     for sqr = n then (mod (* sqr sqr) modulus)
     when (logbitp i exponent) do
        (setf result (mod (* result sqr) modulus))
        finally (return result)))

(defun is-prime (n k)
  "Miller Rabin primailty test implemented using the algorithm from
http://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test"
  (let* ((n-1 (1- n))
	 (n-4 (- n 4))
	 (s 0) d
	 (tmp n-1))
    ;; write n − 1 as 2s·d with d odd by factoring powers of 2 from n − 1
    (loop
       (multiple-value-bind (q r)
	   (floor tmp 2)
	 (if (= r 0)
	     (progn
	       (setf tmp q)
	       (incf s))
	     (progn
	       (setf d tmp)
	       (return)))))
    ;(format t "s: ~A d: ~A~%" s d)
    (dotimes (i k)
      (let* ((a (+ 2 (random n-4)))
	     (x (expt-mod a d n)))
	;(format t "a: ~A~%" a)
	;(format t "x: ~A~%" x)
	(when (or (= x 1) (= x n-1))
	  (go end))
	(dotimes (r s)
	  (setf x (expt-mod x 2 n))
	  ;(format t "*x: ~A~%" x)
	  (when (= x 1)
	    (return-from is-prime nil))
	  (when (= x n-1)
	    (go end)))
	(return-from is-prime nil))
      end))
    t)

(defun gen-prime (&optional (num-bits 1024) (strength 128))
  "generate a probably random prime number of the given number of bits
using strength iterations to verify primality using the miller-rabin
primality test"
  (let ((ndigits (/ num-bits 4))
	(nstr (make-array '(0) :element-type 'base-char :fill-pointer 0 :adjustable t))
	(*print-base* 16))
    (with-output-to-string (s nstr)
      (let ((first-digit (random 16)))
	;; ensure the 2 highest bits are set on first digit
	(setf first-digit (logior first-digit 12))
	(format s "~A" first-digit))
      ;; generate the rest of the digits
      (dotimes (i (- ndigits 2))
	(format s "~A" (random 16)))
      ;; ensure number is odd
      (format s "~A" (logior (random 16) 1)))
    (let ((n (parse-integer nstr :radix 16)))
      (declare (integer n))
      (loop
	   (if (and (/= (mod n +E+) 1)
		    (is-prime n strength))
	       (return-from gen-prime n)
	       (incf n 2))))))

(defun modular-inverse (u v)
  "compute the multiplicative inverse of u modulo v, u-1 (mod v), and
returns either the inverse as a positive integer less than v, or zero
if no inverse exists."
  (let ((u1 1)
	(u3 u)
	(v1 0)
	(v3 v)
	(iter 1))
  (loop
     (when (= v3 0) (return))
     (let* ((q (floor u3 v3))
	    (t3 (mod u3 v3))
	    (t1 (+ u1 (* q v1))))
       (setf u1 v1
	     v1 t1
	     u3 v3
	     v3 t3
	     iter (* iter -1))))
  (when (/= u3 1)
    (return-from modular-inverse 0))
  (when (< iter 0)
    (return-from modular-inverse (- v u1)))
  (return-from modular-inverse u1)))

(defun octets-to-integer (octet-vec &key (start 0) end (big-endian t) n-bits)
  (declare (type (simple-array (unsigned-byte 8) (*)) octet-vec))
  (let ((end (or end (length octet-vec))))
    (multiple-value-bind (complete-bytes extra-bits)
        (if n-bits
            (truncate n-bits 8)
            (values (- end start) 0))
      (declare (ignorable complete-bytes extra-bits))
      (if big-endian
          (do ((j start (1+ j))
               (sum 0))
              ((>= j end) sum)
            (setf sum (+ (aref octet-vec j) (ash sum 8))))
          (loop for i from (- end start 1) downto 0
                for j from (1- end) downto start
                sum (ash (aref octet-vec j) (* i 8)))))))

(defun integer-to-octets (bignum &key (n-bits (integer-length bignum))
                                (big-endian t))
  (let* ((n-bytes (ceiling n-bits 8))
         (octet-vec (make-array n-bytes :element-type '(unsigned-byte 8))))
    (declare (type (simple-array (unsigned-byte 8) (*)) octet-vec))
    (if big-endian
        (loop for i from (1- n-bytes) downto 0
              for index from 0
              do (setf (aref octet-vec index) (ldb (byte 8 (* i 8)) bignum))
              finally (return octet-vec))
        (loop for i from 0 below n-bytes
              for byte from 0 by 8
              do (setf (aref octet-vec i) (ldb (byte 8 byte) bignum))
              finally (return octet-vec)))))

(defmacro sha256 (msg)
  `(ironclad:digest-sequence :sha256 ,msg))
(defmacro base64enc (string)
  `(base64:string-to-base64-string ,string))
(defmacro base64dec (base64-string)
  `(base64:base64-string-to-string ,base64-string))

(defstruct rsa-key
  name name-base64 length n e d)

(defvar *rsa-key-db* (make-hash-table :test #'equal))

(defun rsa-gen-key (name &optional (length 2048))
  "generate n, e and d for use with make-rsa-keys"
    (let* ((length/2 (/ length 2))
	   (p (gen-prime length/2))
	   (q (gen-prime length/2))
	   (n (* p q))
	   (phi (* (1- p) (1- q)))
	   (d (modular-inverse +E+ phi))
	   (base64-name (base64enc name)))
      (setf (gethash base64-name *rsa-key-db*)
	    (make-rsa-key :name name :name-base64 base64-name :length length :n n :e +E+ :d d))))

(defun rsa-save-key (key filename)
	"save rsa key struct to file"
  (with-open-file (s filename :direction :output)
		  (format s "~S" key)))

(defun rsa-load-key (filename)
	"load rsa key from file and store it into key internal database"
  (with-open-file (s filename)
		  (let ((key (read s)))
		    (setf (gethash (rsa-key-name-base64 key) *rsa-key-db*) key))))

(defun rsa-list-keys ()
	"List all stored rsa keys from internal database"
  (maphash (lambda (key value)
	     (declare (ignore key))
	     (format t
		     "Name: ~A~%Name (Base64): ~A~%Length: ~A~%~%"
		     (rsa-key-name value)
		     (rsa-key-name-base64 value)
		     (rsa-key-length value)))
	   *rsa-key-db*))

(defun rsa-find-key (name)
	"find key by name in internal database"
  (maphash (lambda (key value)
	     (declare (ignore key))
	     (when (string= name (rsa-key-name value))
	       (return-from rsa-find-key value)))
	   *rsa-key-db*))
  
(defconstant rsa-num-random-padding-bytes 16)

(defun rsa-encrypt-text (rsa-key msg)
	"encrypt text message with given rsa key"
  (when (> (+ (length msg) 2)
	   (/ (rsa-key-length rsa-key) 8))
      (error "rsa-encrypt-text: message to is too long to encrypt with given key length"))
  (let* ((n (rsa-key-n rsa-key))
	 (e (rsa-key-e rsa-key))
	 (d (rsa-key-d rsa-key))
	 (random-bytes (let (x)
			 (dotimes (i rsa-num-random-padding-bytes)
			   (push (random 256) x))
			 (coerce x '(simple-array (unsigned-byte 8) (*)))))
	 (msg-octets (concatenate '(simple-array (unsigned-byte 8) (*))
				  random-bytes
				  (flexi-streams:string-to-octets
				   (concatenate 'string
						"( \""
						(rsa-key-name-base64 rsa-key)
						"\" \"" (base64enc msg) "\")"))))
	 (sig (integer-to-octets
	       (expt-mod (octets-to-integer (sha256 msg-octets)) d n))) ; s = m^d mod n.
	 msg-length msg-length-octets)
    (setf msg-octets (integer-to-octets (expt-mod (octets-to-integer msg-octets) e n)))
    (setf msg-length (length msg-octets))
    (setf msg-length-octets (integer-to-octets msg-length))
    (if (= (length msg-length-octets) 1) ; make msg length 2 bytes
	(setf msg-length-octets (concatenate '(simple-array (unsigned-byte 8) (*))
					     #(0) msg-length-octets)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
		 msg-length-octets
		 msg-octets
		 sig)))
	
(defun rsa-decrypt-text (rsa-key msg+sig)
	"decrypt rsa-encrypted message using rsa key"
  (let* ((n (rsa-key-n rsa-key))
	 (d (rsa-key-d rsa-key))
	 (msg-len (octets-to-integer (subseq msg+sig 0 2)))
	 (msg-sexp (flexi-streams:octets-to-string
		    (subseq (integer-to-octets
			     (expt-mod (octets-to-integer (subseq msg+sig 2 (+ 2 msg-len))) d n))
			    rsa-num-random-padding-bytes)))
	 (sig (subseq msg+sig (+ 2 msg-len)))
	 (msg (let ((*read-eval* nil))
		    (read-from-string msg-sexp)))
	 (msg-from (base64dec (first msg)))
	 (msg-text (base64dec (second msg))))
    (declare (ignore sig))
    (values msg-from msg-text)))
    
;read file at one shot
(defun file-at-once (filespec &rest open-args)
	"file reading function into string at once"
	(with-open-stream (stream (apply #'open filespec open-args))
	(let* ((buffer
		(make-array (file-length stream)
			:element-type
			(stream-element-type stream)
			:fill-pointer t))
		(position (read-sequence buffer stream)))
	(setf (fill-pointer buffer) position)
	buffer)))

;convert encrypted vector to base64 string
(defun vector-to-base64(vec)
	(cl-base64:string-to-base64-string (flexi-streams:octets-to-string vec)))

;convert base64 string to encrypted vector
(defun base64-to-vector(base64string)
	(flexi-streams:string-to-octets (cl-base64:BASE64-STRING-TO-STRING base64string)))

;encrypt-and-save functionality
(defun rsa-encrypt-and-save (rsa-key msg filespec &rest open-args)
	"encrypt msg by rsa key and save to file, you can provide additional parameters to open call"
	(let ((cyphertext (rsa-encrypt-text rsa-key msg)))
		(with-open-stream (stream (apply #'open filespec :direction :output open-args) )
			(princ (vector-to-base64 cyphertext) stream))))

;load-and-decrypt functionality
(defun rsa-load-and-decrypt (rsa-key filename )
	"load and decrypt message from file using rsa key"
	;load encrypted msg
	;decrypt msg by rsa key 
	(let ((msg+sig (base64-to-vector (file-at-once filename))))
		 (rsa-decrypt-text rsa-key msg+sig)))

(defun rsa-save-db (filespec &rest open-args)
	"save internal rsa key database to file"
	(declare (special *rsa-key-db*))
	(with-open-stream (stream (apply #'open filespec :direction :output open-args))
		(maphash #'(lambda(key value)(declare (ignore key))(format stream "~S" value)) *rsa-key-db*)))

(defun rsa-load-db (filespec &rest open-args)
	"loads keys form file to internal database, does not clear internal db
so you can issue function multiple times to populate db from multiple files
rsa keys with the same name will be overwritten in internal db with latest occurence"
	(declare (special *rsa-key-db*))
	(with-open-stream (stream (apply #'open filespec :direction :input :if-does-not-exist :error open-args))
		(loop for key = (read stream nil)
			while key do (setf (gethash (rsa-key-name-base64 key) *rsa-key-db*) key))))

