#lang racket
(require libkenji)
(require natrium-crypt)
(require math)
(provide unidh-generate-keys
         unidh-calculate-secret
         unidh-key-length)

;; Implements Ian Goldberg's UniformDH scheme.

;; *** NOT SECURE!!! DO NOT USE FOR OTHER THAN OBFUSCATION!!! TIMING ATTACKS!!! ***

(define group-5
  #xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF)
(define unidh-key-length (/ 1536 8))

(define (unidh-generate-keys)
  (define priv (random-bytes unidh-key-length))
  (bytes-set! priv 0 0)
  (define publ (number->le
                (with-modulus group-5
                  (modexpt 2 (le->number priv))) unidh-key-length))
  (values priv 
          (if (< 0.5 (secrandom))
              (number->le
               (- group-5
                  (le->number publ)) unidh-key-length)
              publ)))

(define (unidh-calculate-secret our-priv their-publ)
  (number->le
   (with-modulus group-5
     (modexpt (le->number their-publ) (le->number our-priv)))
   unidh-key-length))

(module+ test
  (require rackunit)
  (define-values (s1 p1) (unidh-generate-keys))
  (define-values (s2 p2) (unidh-generate-keys))
  (check-equal? (unidh-calculate-secret s1 p2)
                (unidh-calculate-secret s2 p1)))