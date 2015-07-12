#lang racket
(require libkenji)
(require natrium-crypt)
(require "uniformdh.rkt")
(provide llobfs-handshake/server
         llobfs-handshake/client)

(define (llobfs-make-ports read-chug
                           write-chug
                           in out)
  (define input
    (make-input-port/sane
     'llobfs-input
     in
     (lambda (bts)
       (define thing (read-bytes-avail! bts in))
       (cond
         [(eof-object? thing) thing]
         [else (atomic (bytes-copy! bts 0 (read-chug (subbytes bts 0 thing))))
               thing]))
     (lambda ()
       (close-port in))))
  (define output
    (let ()
      (make-output-port
       'llobfs-output
       out
       (lambda (to-write start-idx end-idx buffer? breaks?)
         (write-bytes 
          (write-chug (subbytes to-write start-idx end-idx))
          out)
         (- end-idx start-idx))
       (lambda ()
         (close-output-port out)))))
  (values input output))

(define (llobfs-handshake/server server-secret in out)
  ;; Wait until client sends proof that they have our secret
  (define nonce (read-bytes 32 in))
  (define ourhash (read-bytes 32 in))
  (unless (bytes-equal? ourhash
                        (sechash server-secret nonce))
    (error 'llobfs-handshake/server
           "Client failed to prove knowledge of our secret. ~v ~v"
           (sechash ourhash nonce)
           (sechash server-secret nonce)))
  ;; Generate our ephemeral keys
  (define-values (eph-priv eph-pub) (unidh-generate-keys))
  ;; Send ephemeral key
  (write-bytes eph-pub out)
  (flush-output out)
  ;; Read their ephemeral key
  (define their-eph-pub (read-bytes unidh-key-length in))
  ;; Compute shared secret
  (define shared-secret (unidh-calculate-secret eph-priv their-eph-pub))
  ;; Define in and out chuggers
  (define read-key (sechash shared-secret #"llobfs-upstream-key"))
  (define write-key (sechash shared-secret #"llobfs-downstream-key"))
  (define read-chug (chacha20-crypter read-key (make-bytes chacha20-nonce-length)))
  (define write-chug (chacha20-crypter write-key (make-bytes chacha20-nonce-length)))
  ;; Make ports
  (llobfs-make-ports read-chug write-chug in out))

(define (llobfs-handshake/client server-secret in out)
  ;; Prove knowledge of server secret
  (define nonce (random-bytes 32))
  (write-bytes nonce out)
  (define keyed-hash (sechash server-secret nonce))
  (write-bytes keyed-hash out)
  (flush-output out)
  ;; Generate our keys
  (define-values (eph-priv eph-pub) (unidh-generate-keys))
  ;; Read their ephemeral key
  (define their-eph-pub (read-bytes unidh-key-length in))
  ;; Send over our key
  (write-bytes eph-pub out)
  (flush-output out)
  ;; Compute shared secret
  (define shared-secret (unidh-calculate-secret eph-priv their-eph-pub))
  ;; In and out chuggers
  (define read-key (sechash shared-secret #"llobfs-downstream-key"))
  (define write-key (sechash shared-secret #"llobfs-upstream-key"))
  (define read-chug (chacha20-crypter read-key (make-bytes chacha20-nonce-length)))
  (define write-chug (chacha20-crypter write-key (make-bytes chacha20-nonce-length)))
  ;; Make ports
  (llobfs-make-ports read-chug write-chug in out))