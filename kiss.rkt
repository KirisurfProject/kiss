#lang racket
(require natrium-crypt)
(require libkenji)
(require "hlobfs.rkt")
(require "llobfs.rkt")
(provide kiss-handshake/server
         kiss-handshake/client)

;; Utilities

(struct kiss-segment
  (type ; 0: data, 255: EOF
   body))

(define (kiss-segment->bytes ksg)
  (match ksg
    [(kiss-segment type body)
     (bytes-append (bytes type)
                   body)]))

(define (bytes->kiss-segment bts)
  (kiss-segment (bytes-ref bts 0)
                (subbytes bts 1)))

;; Interface functions

(define (kiss-handshake/server perm-priv in out)
  ;; Ephemeral ECDH
  (define-values (eph-priv eph-pub) (ecdh-generate-keys))
  ;; Signature
  (define signat (eddsa-sign perm-priv eph-pub))
  ;; Public key
  (define perm-pub (eddsa-private->public perm-priv))
  ;; Write them out
  (write-bytes
   (bytes-append eph-pub
                 signat
                 perm-pub) out)
  (flush-output out)
  ;; Read their public key (unauth)
  (define their-eph-pub (read-bytes ecdh-key-length in))
  ;; Calculate the shared secret
  (define raw-secret (ecdh-calculate-secret eph-priv their-eph-pub))
  ;; Create read and write keys
  (define read-key (sechash raw-secret #"kiss3.0-upstream-key"))
  (define write-key (sechash raw-secret #"kiss3.0-downstream-key"))
  ;; Generate the ports
  (kiss-make-ports read-key write-key in out))

(define (kiss-handshake/client their-pkhash in out)
  ;; Read their things
  (define their-eph-pub (read-bytes ecdh-key-length in))
  (define their-signature (read-bytes eddsa-signature-length in))
  (define their-perm-pub (read-bytes eddsa-public-key-length in))
  ;; Verify
  (when their-pkhash
    (unless (and (bytes-equal? (sechash their-perm-pub) their-pkhash)
               (eddsa-authentic? their-perm-pub their-signature their-eph-pub))
    (error "Server provided incorrect authentication! Man in the middle?")))
  ;; Generate and send my things
  (define-values (eph-priv eph-pub) (ecdh-generate-keys))
  (write-bytes eph-pub out)
  (flush-output out)
  ;; Do the secret
  (define raw-secret (ecdh-calculate-secret eph-priv their-eph-pub))
  (define read-key (sechash raw-secret #"kiss3.0-downstream-key"))
  (define write-key (sechash raw-secret #"kiss3.0-upstream-key"))
  ;; Generate ports
  (kiss-make-ports read-key write-key in out))

;; Core function

(define (kiss-make-ports read-key write-key in out)
  (define read-lock (make-semaphore 1))
  (define write-lock (make-semaphore 1))
  (define read-ctr 0)
  (define write-ctr 0)
  (define read-closed? #f)
  (define write-closed? #f)
  (define (read-in)
    (with-semaphore read-lock
      (cond
        [read-closed? eof]
        [else
         (with-handlers ([exn? (lambda (ex)
                                 (set! read-closed? #t)
                                 (raise ex))])
           (define len (integer-bytes->integer (read-bytes 2 in)
                                               #f
                                               #f))
           (define nonce (let ([ctr (integer->integer-bytes read-ctr
                                                            8
                                                            #f
                                                            #f)])
                           (bytes-append ctr (make-bytes 16))))
           (set! read-ctr (add1 read-ctr))
           (define thing (read-bytes len in))
           (define plain
             (secretbox-open read-key
                             nonce
                             (subbytes thing secretbox-mac-length)
                             (subbytes thing 0 secretbox-mac-length)))
           (match (bytes->kiss-segment plain)
             [(kiss-segment 0 bdy) bdy]
             [(kiss-segment (not 0) bdy) (set! read-closed? #t)
                                         eof]))])))
  (define (write-pkt thing-har)
    (define thing (kiss-segment->bytes thing-har))
    (define len (integer->integer-bytes (+ secretbox-mac-length
                                           (bytes-length thing))
                                        2
                                        #f
                                        #f))
    (define nonce (let ([ctr (integer->integer-bytes write-ctr
                                                     8
                                                     #f
                                                     #f)])
                    (bytes-append ctr (make-bytes 16))))
    (set! write-ctr (add1 write-ctr))
    (define-values (ciphtext mac)
      (secretbox-seal write-key
                      nonce
                      thing))
    (write-bytes (bytes-append len
                               mac
                               ciphtext) out)
    )
  
  (values
   (make-input-port/buffered
    'kiss-input
    in
    read-in
    (lambda ()
      (with-semaphore read-lock
        (set! read-closed? #t)
        (close-port in))
      ))
   (make-output-port
    'kiss-output
    out
    (lambda (to-write start-idx end-idx buffer? breaks?)
      (with-semaphore write-lock
        (write-pkt (kiss-segment 0 (subbytes to-write start-idx
                                           end-idx))))
      (- end-idx start-idx))
    (lambda ()
      (with-semaphore write-lock
        (when (not write-closed?)
          (write-pkt (kiss-segment 255 #""))
          (set! write-closed? #t))
        (close-port out))
      ))))

(define (kiss-test-server prt privk secr)
  (define listener (tcp-listen prt 256 #t))
  (let loop()
    (define-values (__in __out) (tcp-accept/no-buffer listener))
    (yarn
     (define-values (in out) (kiss-handshake/server privk __in __out))
     (defer (close-port out))
     (defer (close-port in))
     (copy-port in out))
    (loop)))

(define (kiss-test-client prt their pkhash)
  (define listener (tcp-listen prt 256 #t))
  (let loop ()
    (define-values (cin cout) (tcp-accept/no-buffer listener))
    (yarn
     (defer (close-port cin))
     (defer (close-port cout))
     (define-values (__in __out) (tcp-connect/no-buffer "127.0.0.1" their))
     (define-values (in out) (kiss-handshake/client pkhash __in __out))
     (define (destroy)
       (close-port in)
       (close-port out))
     (yarn
      (defer (destroy))
      (copy-port cin out))
     (defer (destroy))
     (copy-port in cout))
    (loop)))